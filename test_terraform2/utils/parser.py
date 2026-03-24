"""Helpers for loading Terraform plan JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def load_plan(plan_path: str | Path) -> Dict[str, Any]:
    path = Path(plan_path)
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_valid_resources(plan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    resources: List[Dict[str, Any]] = []

    for resource in plan_data.get("resource_changes", []):
        actions = resource.get("change", {}).get("actions", [])
        after = resource.get("change", {}).get("after")

        if "delete" in actions or after is None:
            continue

        resources.append(resource)

    return resources
