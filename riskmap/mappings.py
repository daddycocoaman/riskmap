import ast
from collections import namedtuple
import inspect
import json
from datetime import datetime
from functools import wraps
from pathlib import Path
from textwrap import wrap
from typing import Callable, List, NamedTuple

from loguru import logger
from prettytable import PrettyTable
from stix2 import CompositeDataSource, FileSystemSource, Filter

from .utils import CustomEncoder


class AttckMapper:
    """Mapper for ATT&CK Matrix IDs via STIX. Only file system access supported

    Args:
        base_cti_path: Base directory of CTI data.
    """

    def __init__(
        self, base_cti_path: Path, log_path: Path = Path("riskmap.log")
    ) -> None:

        # Configure sources
        self.src = CompositeDataSource()
        self.src.add_data_source(FileSystemSource(base_cti_path / "enterprise-attack"))
        self.src.add_data_source(FileSystemSource(base_cti_path / "mobile-attack"))
        self.src.add_data_source(FileSystemSource(base_cti_path / "ics-attack"))
        self.src.add_data_source(FileSystemSource(base_cti_path / "capec"))

        logger.remove()
        logger.add(sink=log_path, format="{message}")

    def lookup_by_attack_id(self, attack_id: str):
        return self.src.query(
            [
                Filter("external_references.external_id", "=", attack_id),
                Filter("type", "in", ["attack-pattern", "course-of-action"]),
            ]
        )

    def mapping(
        self, *ignore, enterprise: List = [], mobile: List = [], ics: List = []
    ):
        """Maps enterprise, mobile, and ics IDs to a function as a dictionary."""
        if ignore:
            raise TypeError("Mapping arguments must be explicit")

        def decorator(func: Callable):
            @wraps(func)
            def add_attribute(*args, **kwargs):
                ids = {
                    "enterprise": enterprise,
                    "mobile": mobile,
                    "ics": ics,
                }
                try:
                    now = datetime.utcnow()
                    details = func(*args, **kwargs) or {}
                    logger.info(
                        json.dumps(
                            {
                                "command": func.__name__,
                                "startTime": now.strftime("%m/%d/%Y %H:%M:%S"),
                                "endTime": datetime.utcnow().strftime(
                                    "%m/%d/%Y %H:%M:%S"
                                ),
                                "args": args,
                                "kwargs": kwargs,
                                "details": details,
                                "mapping": ids,
                            },
                            cls=CustomEncoder,
                        )
                    )
                except Exception as e:
                    print(e)

            return add_attribute

        return decorator

    def get_map_info(self, map_object_name: str, command: Callable) -> List:
        """Lazy method to retrieve mapping of command to get details"""
        module = ast.parse(inspect.getsource(command))
        definition = []
        for node in ast.walk(module):
            if isinstance(node, ast.FunctionDef):
                for d in node.decorator_list:
                    if d.func.value.id == map_object_name:
                        for kw in d.keywords:
                            param, values = kw.arg, kw.value.elts
                            for v in values:
                                definition += self.lookup_by_attack_id(str(v.value))

                        break
                break
        return definition

    def describe(self, map_object_name: str, command: Callable) -> namedtuple:
        definition = self.get_map_info(map_object_name, command)

        references = []
        detections = []
        mitigations = []

        for pattern in definition:

            if pattern.type == "attack-pattern":
                if hasattr(pattern, "x_mitre_detection"):
                    detections.append((pattern.name, pattern.x_mitre_detection))
            elif pattern.type == "course-of-action":
                mitigations.append((pattern.name, pattern.description))

            for ref in pattern.external_references:
                if hasattr(ref, "external_id"):
                    if ref.external_id not in references:
                        references.append([ref.external_id, ref.url])

        summarytable = PrettyTable(title="Summary", header=False)
        reftable = PrettyTable(title="References", header=False)
        detecttable = PrettyTable(title="Detections", header=False)
        mititable = PrettyTable(title="Mitigations", header=False)

        summarytable.add_row(["Name", command.__name__])
        summarytable.add_row(["Description", command.__doc__])
        reftable.add_rows(references)
        detecttable.add_rows([[d[0], "\n".join(wrap(d[1]))] for d in detections])
        mititable.add_rows([[m[0], "\n".join(wrap(m[1]))] for m in mitigations])

        summarytable.align = "l"
        reftable.align = "l"
        detecttable.align = "l"
        mititable.align = "l"
        return NamedTuple(
            "Description",
            [
                ("summary_table", PrettyTable),
                ("references_table", PrettyTable),
                ("detections_table", PrettyTable),
                ("mitigations_table", PrettyTable),
            ],
        )(summarytable, reftable, detecttable, mititable)
