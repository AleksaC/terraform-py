from __future__ import annotations

import argparse
import importlib
import os
import subprocess
import sys

from typing import List
from typing import Optional
from typing import Set

PROVIDERS_PLATFORMS = ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64")


def get_dirs(filenames: List[str]) -> Set[str]:
    dirs = set(map(lambda filename: os.path.dirname(filename), filenames))

    if "" in dirs:
        dirs.remove("")
        dirs.add(".")

    return dirs


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


def providers_lock(dir: str, platforms: Optional[List[str]] = None) -> int:
    if not platforms:
        platforms = []
    platforms = [f"-platform={platform}" for platform in platforms]
    return run_terraform_command("providers", "lock", *platforms, cwd=dir)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    fmt_parser = subparsers.add_parser("fmt")
    fmt_parser.add_argument("filenames", nargs="*")

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("filenames", nargs="*")

    providers_lock_parser = subparsers.add_parser("providers_lock")
    providers_lock_parser.add_argument(
        "--platform", action="append", choices=PROVIDERS_PLATFORMS
    )
    providers_lock_parser.add_argument("cwd")

    args = parser.parse_args(argv)

    status_code = 0

    module = importlib.import_module(__name__)
    command = getattr(module, args.command)

    if args.command == "providers_lock":
        status_code |= command(args.cwd, args.platform)
    else:
        for dir in get_dirs(args.filenames):
            status_code |= command(dir)

    return status_code
