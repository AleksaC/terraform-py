from __future__ import annotations

import argparse
import os
import subprocess
import sys

from typing import List
from typing import Optional
from typing import Set


def get_dirs(filenames: List[str]) -> Set[str]:
    return set(map(lambda filename: os.path.dirname(filename), filenames))


def run_terraform_command(command: str, *args: str, **kwargs) -> int:
    global_options = kwargs.pop("global_options", [])
    options = kwargs.pop("options", [])

    res = subprocess.run(
        ["terraform", *global_options, command, *options, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )

    print(res.stdout, end="")
    print(res.stderr, file=sys.stderr, end="")

    return res.returncode


def fmt(dir: str) -> int:
    return run_terraform_command("fmt", dir)


def validate(dir: str) -> int:
    run_terraform_command("init", "-backend=false", cwd=dir)
    return run_terraform_command("validate", cwd=dir)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["fmt", "validate"])
    parser.add_argument("filenames", nargs="*")
    args = parser.parse_args(argv)

    status_code = 0
    command = fmt if args.command == "fmt" else validate
    for dir in get_dirs(args.filenames):
        status_code |= command(dir)

    return status_code
