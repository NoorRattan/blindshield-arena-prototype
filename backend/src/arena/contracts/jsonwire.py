"""Single strict raw JSON boundary. Errors intentionally omit supplied values."""

import json
import math
from typing import Any, TypeVar

from pydantic import BaseModel, TypeAdapter, ValidationError


MAX_BODY_BYTES = 70_000
MAX_DEPTH = 16
M = TypeVar("M", bound=BaseModel)


class ContractError(ValueError):
    def __init__(self, code: str = "INVALID_SCHEMA"):
        self.code = code
        super().__init__(code)


def _pairs(items: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ContractError()
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ContractError()


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ContractError()
    return result


def _depth(value: Any, level: int = 0) -> None:
    if level > MAX_DEPTH:
        raise ContractError()
    if isinstance(value, dict):
        for child in value.values():
            _depth(child, level + 1)
    elif isinstance(value, list):
        for child in value:
            _depth(child, level + 1)


def strict_json(body: bytes) -> dict:
    if type(body) is not bytes:
        raise ContractError()
    if len(body) > MAX_BODY_BYTES:
        raise ContractError("BODY_TOO_LARGE")
    try:
        value = json.loads(body.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
        if type(value) is not dict:
            raise ContractError()
        _depth(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ContractError):
            raise
        raise ContractError() from None


def load_wire(schema: type[M] | TypeAdapter, body: bytes) -> M:
    """Never bypass raw parsing with model_validate_json at an untrusted boundary."""
    value = strict_json(body)
    try:
        if isinstance(schema, TypeAdapter):
            return schema.validate_python(value)
        return schema.model_validate(value)
    except (ValidationError, ValueError, TypeError):
        raise ContractError() from None
