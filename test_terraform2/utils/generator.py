"""Helpers for building diagnosis output objects."""

from __future__ import annotations

from typing import Any, Dict


def create_finding(
    check_code: str,
    check_name: str,
    resource_type: str,
    resource_name: str,
    status: str,
    details: Any,
) -> Dict[str, Any]:
    return {
        "check_code": check_code,
        "check_name": check_name,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "status": status,
        "severity": "HIGH" if status == "vulnerable" else "INFO",
        "details": details,
    }
