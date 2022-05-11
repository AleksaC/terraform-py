#!/usr/bin/env python

import base64
import itertools
import json
import os
import re
import subprocess
import sys
from urllib.request import Request
from urllib.request import urlopen

from typing import Any
from typing import NamedTuple
from typing import Optional

from jinja2 import Template


VERSION_RE = re.compile("^v?(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)$")

OS = ("darwin", "linux", "windows")
ARCH = ("amd64", "arm64")

TEMPLATES_DIR = "templates"
PACKAGE_DIR = "terraform_py"

REPO = "hashicorp/terraform"
MIRROR_REPO = "AleksaC/terraform-py"


class Version(NamedTuple):
    major: int
    minor: int
    patch: int

    @classmethod
    def from_string(cls, version: str) -> "Version":
        if match := re.match(VERSION_RE, version):
            return cls(*map(int, match.groups()))

        raise ValueError("Invalid version", version)

    def __repr__(self):
        return f"{self.major}.{self.minor}.{self.patch}"


def _get(url: str, headers: Optional[dict[str, str]] = None) -> dict:
    if headers is None:
        headers = {}

    req = Request(url, headers=headers)
    resp = urlopen(req, timeout=30)

    return resp


def get_json(url: str, headers: Optional[dict[str, str]] = None) -> dict:
    return json.loads(_get(url, headers).read())


def get_text(url: str, headers: Optional[dict[str, str]] = None) -> str:
    return _get(url, headers).read().decode()


def get_versions(repo: str, *, from_releases: bool = True) -> list[str]:
    gh_token = os.environ["GH_TOKEN"]
    auth = base64.b64encode(f"AleksaC:{gh_token}".encode()).decode()
    base_url = "https://api.github.com/repos/{}/{}?per_page=100&page={}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Basic {auth}",
    }

    releases = []
    page = 1
    while releases_page := get_json(
        base_url.format(repo, "releases" if from_releases else "tags", page),
        headers=headers,
    ):
        releases.extend(releases_page)
        page += 1

    if from_releases:
        return [
            release["tag_name"]
            for release in releases
            if not release["draft"] and not release["prerelease"]
        ]

    return [release["name"] for release in releases]


def get_missing_versions(repo: str, mirror_repo: str) -> list[Version]:
    versions = get_versions(repo)
    mirrored = set(
        map(Version.from_string, get_versions(mirror_repo, from_releases=False))
    )
    missing = []

    for v in reversed(versions):
        version = Version.from_string(v)
        if version not in mirrored:
            missing.append(version)

    return missing


def get_archives(version: Version) -> dict[str, tuple[str, str]]:
    checksum_url = (
        f"https://releases.hashicorp.com/terraform/"
        f"{version}/terraform_{version}_SHA256SUMS"
    )
    checksums = get_text(checksum_url).splitlines()

    versions = {
        f"terraform_{version}_{os}_{arch}.zip": (os, arch)
        for os, arch in itertools.product(OS, ARCH)
    }

    archives = {}

    for checksum in checksums:
        sha, archive = checksum.split()
        if archive in versions:
            os, arch = versions[archive]
            archives[f"{os}_{arch}"] = (archive, sha)

    return archives


def render_setup_template(vars: dict[str, Any]) -> None:
    with open(os.path.join(TEMPLATES_DIR, "setup.py.j2")) as f:
        setup_py_template = f.read()

    template = Template(setup_py_template, keep_trailing_newline=True)

    with open("setup.py", "w") as f:
        f.write(template.render(**vars))


def push_tag(version: Version) -> None:
    subprocess.run(["./tag.sh", f"v{version}"], check=True)


def main():
    versions = get_missing_versions(REPO, MIRROR_REPO)

    for version in versions:
        print(f"Adding new version: v{version}")
        archives = get_archives(version)
        render_setup_template({"tf_version": str(version), "archives": str(archives)})
        push_tag(version)

    return 0


if __name__ == "__main__":
    sys.exit(main())
