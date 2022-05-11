#!/usr/bin/env python3

import hashlib
import http
import io
import os.path
import platform
import stat
import tarfile
import urllib.request
import zipfile
from distutils.command.build import build as orig_build
from distutils.core import Command

from setuptools import setup
from setuptools.command.install import install as orig_install


TERRAFORM_VERSION = "0.14.6"
ARCHIVE_SHA256 = {'darwin_amd64': ('terraform_0.14.6_darwin_amd64.zip', '126e1c9e058f12c247a194db5a9567e59ec755cbc0211cd5d58c8b7d37412b2c'), 'linux_amd64': ('terraform_0.14.6_linux_amd64.zip', '63a5a45edde435fa3f278c86ce96346ee7f6b204ea949734f26f963b7dbc1074'), 'linux_arm64': ('terraform_0.14.6_linux_arm64.zip', '512791e0a6185b7a895cfe112c289d5d2fb816112406772134343bbe4f1f4a63'), 'windows_amd64': ('terraform_0.14.6_windows_amd64.zip', '8f9984006386d32fb5220d012dbeb9c6e654a6fa1476775114b97b343ec4fa4a')}


def get_download_url() -> str:
    os, arch = platform.system().lower(), platform.machine().lower()
    if (
        os == "windows"
        or "x86" in arch
        or "amd" in arch
        or "i386" in arch
        or "i686" in arch
    ):
        arch = "amd"
    elif "arm" in arch or arch == "aarch64":
        arch = "arm"

    archive, sha256 = ARCHIVE_SHA256[f"{os}_{arch}64"]
    url = f"https://releases.hashicorp.com/terraform/" f"{TERRAFORM_VERSION}/{archive}"

    return url, sha256


def download(url: str, sha256: str) -> bytes:
    with urllib.request.urlopen(url) as resp:
        code = resp.getcode()
        if code != http.HTTPStatus.OK:
            raise ValueError(f"HTTP failure. Code: {code}")
        data = resp.read()

    checksum = hashlib.sha256(data).hexdigest()
    if checksum != sha256:
        raise ValueError(f"sha256 mismatch, expected {sha256}, got {checksum}")

    return data


def extract(url: str, data: bytes) -> bytes:
    with io.BytesIO(data) as bio:
        if ".tar." in url:
            with tarfile.open(fileobj=bio) as tarf:
                for info in tarf.getmembers():
                    if info.isfile() and (
                        info.name.endswith("terraform")
                        or info.filename.endswith(".exe")
                    ):
                        return tarf.extractfile(info).read()
        elif url.endswith(".zip"):
            with zipfile.ZipFile(bio) as zipf:
                for info in zipf.infolist():
                    if not info.is_dir() and (
                        info.filename.endswith(".exe")
                        or info.filename.endswith("terraform")
                    ):
                        return zipf.read(info.filename)

    raise AssertionError(f"unreachable {url}")


def save_executable(data: bytes, base_dir: str):
    exe = "terraform" if platform.system() != "Windows" else "terraform.exe"
    output_path = os.path.join(base_dir, exe)
    os.makedirs(base_dir)

    with open(output_path, "wb") as fp:
        fp.write(data)

    # Mark as executable.
    # https://stackoverflow.com/a/14105527
    mode = os.stat(output_path).st_mode
    mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    os.chmod(output_path, mode)


class build(orig_build):
    sub_commands = orig_build.sub_commands + [("fetch_binaries", None)]


class install(orig_install):
    sub_commands = orig_install.sub_commands + [("install_terraform", None)]


class fetch_binaries(Command):
    build_temp = None

    def initialize_options(self):
        pass

    def finalize_options(self):
        self.set_undefined_options("build", ("build_temp", "build_temp"))

    def run(self):
        # save binary to self.build_temp
        url, sha256 = get_download_url()
        archive = download(url, sha256)
        data = extract(url, archive)

        save_executable(data, self.build_temp)


class install_terraform(Command):
    description = "install the terraform executable"
    outfiles = ()
    build_dir = install_dir = None

    def initialize_options(self):
        pass

    def finalize_options(self):
        # this initializes attributes based on other commands' attributes
        self.set_undefined_options("build", ("build_temp", "build_dir"))
        self.set_undefined_options(
            "install",
            ("install_scripts", "install_dir"),
        )

    def run(self):
        self.outfiles = self.copy_tree(self.build_dir, self.install_dir)

    def get_outputs(self):
        return self.outfiles


command_overrides = {
    "install": install,
    "install_terraform": install_terraform,
    "build": build,
    "fetch_binaries": fetch_binaries,
}


try:
    from wheel.bdist_wheel import bdist_wheel as orig_bdist_wheel

    class bdist_wheel(orig_bdist_wheel):
        def finalize_options(self):
            orig_bdist_wheel.finalize_options(self)
            # Mark us as not a pure python package
            self.root_is_pure = False

        def get_tag(self):
            _, _, plat = orig_bdist_wheel.get_tag(self)
            # We don't contain any python source, nor any python extensions
            return "py2.py3", "none", plat

    command_overrides["bdist_wheel"] = bdist_wheel
except ImportError:
    pass

setup(version=f"{TERRAFORM_VERSION}", cmdclass=command_overrides)
