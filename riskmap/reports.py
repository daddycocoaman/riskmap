import json
from os import write
import sys
from itertools import chain
from pathlib import Path
from typing import List

import pandas as pd

from .mappings import AttckMapper


class RiskmapReportGenerator:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.mapper = AttckMapper()

    def _lookup_logs(self) -> List:
        logs = []
        with open(self.path) as logfile:
            logs = [json.loads(line) for line in logfile.read().splitlines()]

        for log in logs:
            mappings = list(chain(*log["mapping"].values()))
            definitions = {m: self.mapper.lookup_by_attack_id(m) for m in mappings}

            references = {}
            for m, definition in definitions.items():
                for pattern in definition:
                    for ref in pattern.external_references:
                        if hasattr(ref, "external_id"):
                            if ref.external_id not in [r[0] for r in references]:
                                references[ref.external_id] = ref.url
            log["extended_lookup"] = references
        return logs

    def to_excel(self, output: Path = Path("./rrg-report.xlsx")):
        logs = self._lookup_logs()
        for log in logs:
            for col, data in log.items():
                if isinstance(data, dict):
                    log[col] = "\n".join([f"{k}: {v}" for k, v in data.items()])
                elif isinstance(data, list):
                    log[col] = "\n".join(data)

        writer = pd.ExcelWriter(output, engine="xlsxwriter")
        df = pd.DataFrame(logs)
        df.to_excel(writer)

        workbook = writer.book
        worksheet = writer.sheets["Sheet1"]

        cell_format = workbook.add_format()
        cell_format.set_align("left")
        cell_format.set_text_wrap()

        worksheet.set_column("A:Z", None, cell_format)
        writer.save()