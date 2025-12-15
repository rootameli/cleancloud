import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass
class ModuleDefinition:
    """Definition for an executable module."""

    id: str
    display_name: str
    type: str
    working_dir: Path
    entrypoint: list[str]
    timeout: int
    output_paths: Dict[str, str]


MODULES_REGISTRY: Dict[str, ModuleDefinition] = {
    "leancloud_js": ModuleDefinition(
        id="leancloud_js",
        display_name="LeanCloud JS Scanner",
        type="subprocess",
        working_dir=Path(os.getenv("LEAN_MODULE_PATH", "Modules_CleanCloud/js.scanner")),
        entrypoint=["go", "run", "main.go"],
        timeout=600,
        output_paths={"result_dir": "ResultJS"},
    ),
}


def get_module(module_id: str) -> Optional[ModuleDefinition]:
    """Return module definition by id."""

    return MODULES_REGISTRY.get(module_id)


def module_id_for_type(module_type: str) -> Optional[str]:
    """Map module type string to registry id."""

    # For now, map everything to leancloud module until more are added
    return "leancloud_js" if module_type else None
