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


TERRAFORM_VERSION = "1.15.8"
ARCHIVE_SHA256 = {'darwin_amd64': ('terraform_1.15.8_darwin_amd64.zip', 'e2e812e783771159bf758fd4e55d6dc9bb08f63e2af2c63d212721807a02c5dc'), 'darwin_arm64': ('terraform_1.15.8_darwin_arm64.zip', 'f210110c5698b94d803a7a63cdb0251b5455c150841478808e2bbb343f95ed68'), 'linux_amd64': ('terraform_1.15.8_linux_amd64.zip', 'd25ce7b6902013ad905db3d2eab0be4cd905887fe88b81a6171b8d5503c31f3d'), 'linux_arm64': ('terraform_1.15.8_linux_arm64.zip', '8891e9dcedc9e3b8950bc6af9d4d8af1f4cfade3062f53b9dc403a89f6ce8c9c'), 'windows_amd64': ('terraform_1.15.8_windows_amd64.zip', '2ff41d2129afb1982733c132c61a8d6ef038f879f3aeede7fc28b8b8b24acf02'), 'windows_arm64': ('terraform_1.15.8_windows_arm64.zip', 'ffd9399a37ee8123263d84ec5c00d09d7704f9997cb345d7c9cac56c3fc1348e')}


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
                    if info.isfile() and info.name.endswith("terraform"):
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
    os.makedirs(base_dir, exist_ok=True)

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
