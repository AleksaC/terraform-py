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


TERRAFORM_VERSION = "1.15.5"
ARCHIVE_SHA256 = {'darwin_amd64': ('terraform_1.15.5_darwin_amd64.zip', '3687d07c034b3e7deed5b072cd8ae2b34835bcb139baec3fc4f5fd534dabf5ed'), 'darwin_arm64': ('terraform_1.15.5_darwin_arm64.zip', '01137660510005b918bba82154866fbeac4393163d8277c2abe861dfb5842c3c'), 'linux_amd64': ('terraform_1.15.5_linux_amd64.zip', '702b2136af6728c8ff037f843dd2dbce2b7ad88786b7381d1d72aefa250f601c'), 'linux_arm64': ('terraform_1.15.5_linux_arm64.zip', '06e7b48de826146c6d9331ba35b13da12332d8392be30d1dd6b789ba4713fff0'), 'windows_amd64': ('terraform_1.15.5_windows_amd64.zip', '2f652dd854af7b7fbb51301afc55b5ef1d3f6e287be7889d4cc3818df891cd38'), 'windows_arm64': ('terraform_1.15.5_windows_arm64.zip', '45322dc7c9970594166d0981cac64917ee2bb0d24d6b7637f99508eb874541fe')}


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
