import json
from pathlib import Path
from typing import Any


class CustomEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Path):
            return obj.name

        return json.JSONEncoder.default(self, obj)
