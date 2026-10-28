"""Import wire models from arena.contracts.models; parse untrusted bytes with load_wire."""

from .jsonwire import ContractError, load_wire

__all__ = ["ContractError", "load_wire"]
