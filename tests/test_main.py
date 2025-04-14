import os
from glob import glob
from hashlib import sha256
from shutil import copy

import pytest

from terraform_py._main import fmt
from terraform_py._main import get_dirs
from terraform_py._main import main
from terraform_py._main import providers_lock
from terraform_py._main import run_terraform_command
from terraform_py._main import validate


@pytest.fixture
def versions_tf(tmp_path):
    path = tmp_path / "versions.tf"
    file_contents = """\
        terraform {
            required_version = ">= 0.13"
            required_providers {
                aws = {
                source = "hashicorp/aws"
                version = "4.3.0"
                }
            }
        }
    """
    path.write_text(file_contents)

    return path


def test_get_dirs():
    files = glob("testing/**/*.tf", recursive=True)
    dirs = get_dirs(files)

    expected_dirs = {
        os.path.join("testing", "valid"),
        os.path.join("testing", "invalid"),
        os.path.join("testing", "malformatted"),
        os.path.join("testing", "missing-hash"),
        os.path.join("testing", "nested", "invalid"),
        os.path.join("testing", "nested", "malformatted"),
    }

    assert len(dirs) == len(expected_dirs) and all(dir in expected_dirs for dir in dirs)


def test_get_dirs_root(monkeypatch):
    monkeypatch.chdir(os.path.join("testing", "valid"))

    files = glob("*.tf", recursive=True)
    dirs = get_dirs(files)

    assert dirs == {"."}


def test_fmt_valid():
    return_code = run_terraform_command("fmt", "testing/valid", options=["-check"])

    assert return_code == 0


def test_fmt_invalid():
    return_code = run_terraform_command(
        "fmt", "testing/malformatted", options=["-check"]
    )

    assert return_code != 0


def test_fmt_invalid_with_sideefects(capsys, monkeypatch, versions_tf):
    dir = str(versions_tf.parent)
    monkeypatch.chdir(dir)

    assert fmt(dir) == 0

    out, _ = capsys.readouterr()
    assert out == "versions.tf\n"


def test_validate_valid():
    return_code = validate("testing/valid")

    assert return_code == 0


def test_validate_invalid():
    return_code = validate("testing/invalid")

    assert return_code != 0


def test_fmt_invalid_nested():
    return_code = validate("testing/nested/invalid")

    assert return_code != 0


def test_validate_invalid_nested():
    return_code = run_terraform_command(
        "fmt", "testing/nested/malformatted", options=["-check"]
    )

    assert return_code != 0


def test_validate_cli():
    files = glob("testing/**/*.tf", recursive=True)

    assert main(["validate", *files]) != 0


def test_providers_lock_valid():
    return_code = providers_lock("testing/valid")

    assert return_code == 0


def test_providers_lock_missing_hash():
    before_lock = sha256(open("testing/missing-hash/.terraform.lock.hcl", "rb").read())
    return_code = providers_lock("testing/missing-hash")
    after_lock = sha256(open("testing/missing-hash/.terraform.lock.hcl", "rb").read())
    # restore file
    copy("testing/valid/.terraform.lock.hcl", "testing/missing-hash/.terraform.lock.hcl")

    assert return_code == 0
    assert before_lock != after_lock
