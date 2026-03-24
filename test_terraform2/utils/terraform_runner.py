"""Terraform command helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path


def terraform_fmt(target_dir: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["terraform", "fmt", "-recursive"],
        cwd=str(target_dir),
        capture_output=True,
        text=True,
        check=False,
    )
