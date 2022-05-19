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


TERRAFORM_VERSION = "1.2.0"
ARCHIVE_SHA256 = {'darwin_amd64': ('terraform_1.2.0_darwin_amd64.zip', 'f608b1fee818988d89a16b7d1b6d22b37cc98892608c52c22661ca6cbfc3d216'), 'darwin_arm64': ('terraform_1.2.0_darwin_arm64.zip', 'd4df7307bad8c13e443493c53898a7060f77d661bfdf06215b61b65621ed53e9'), 'linux_amd64': ('terraform_1.2.0_linux_amd64.zip', 'b87de03adbdfdff3c2552c8c8377552d0eecd787154465100cf4e29de4a7be1f'), 'linux_arm64': ('terraform_1.2.0_linux_arm64.zip', 'ee80b8635d8fdbaed57beffe281cf87b8b1fd1ddb29c08d20e25a152d9f0f871'), 'windows_amd64': ('terraform_1.2.0_windows_amd64.zip', 'de88c66fbcdca0561d4e6d8d8090d697e97de9bbd97c212ceed21d942e33f937')}


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
