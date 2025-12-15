from typing import Callable, Dict

from .leancloud_js import parse_leancloud_js

ParserFunc = Callable[[str, str, Dict[str, str]], object]

PARSERS: Dict[str, ParserFunc] = {
    "leancloud_js": parse_leancloud_js,
}


def get_parser(module_id: str) -> ParserFunc | None:
    return PARSERS.get(module_id)
