"""Importing this package registers every built-in check."""

from scanner.checks import iam, logging, network, s3  # noqa: F401
from scanner.checks.base import REGISTRY, BaseCheck, register

__all__ = ["REGISTRY", "BaseCheck", "register"]
