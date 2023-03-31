# terraform-py

[![Add new versions](https://github.com/AleksaC/terraform-py/actions/workflows/add-new-versions.yml/badge.svg)](https://github.com/AleksaC/terraform-py/actions/workflows/add-new-versions.yml)
[![Run tests](https://github.com/AleksaC/terraform-py/actions/workflows/tests.yml/badge.svg)](https://github.com/AleksaC/terraform-py/actions/workflows/tests.yml)

pip installable [terraform](https://github.com/hashicorp/terraform) binary with wrapper for pre-commit.

The mechanism by which the terraform binary is downloaded is adapted from
[shellcheck-py](https://github.com/shellcheck-py/shellcheck-py).

## Getting started

### Installation

This package has been built to make it more convenient to run `terraform fmt`
`terraform validate` as pre-commit hooks so it hasn't been published to PyPI.
However you can install it using git:

```shell script
pip install git+https://github.com/AleksaC/terraform-py.git@v1.4.4
```

### pre-commit hooks

Since `terraform fmt` and `terraform validate` take directories as inputs they
can't be used as pre-commit hooks directly. Hence there are wrappers for the
two commands that take list of filenames as input and run the commands on the
directories they are in. To use the hooks include the following config in your
`.pre-commit-config.yaml` file:

```yaml
repos:
  - repo: https://github.com/AleksaC/terraform-py
    rev: v1.4.4
    hooks:
      - id: tf-fmt
      - id: tf-validate
```

## Limitations

This package mirrors all terraform releases currently available on github,
however fmt and validate commands weren't available on the oldest versions
and worked differently in the initial releases. This shouldn't be a problem
since I don't expect versions so old to be used.

Versions before `1.0.3` won't work on Macs with M1 chip since darwin arm builds
weren't available for earlier versions. While x86 binaries would work
I didn't want to support that edge case in the platform detection code as it
won't be needed for the future releases.

`terraform validate` itself isn't particularly fast. In addition to that
`terraform init` needs to be performed before it, making it even slower.
In projects with lots of modules this can get quite slow, so you may need
to set up additional caching beside the one for pre-commit.

## Contact 🙋‍♂️
- [Personal website](https://aleksac.me)
- <a target="_blank" href="http://twitter.com/aleksa_c_"><img alt='Twitter followers' src="https://img.shields.io/twitter/follow/aleksa_c_.svg?style=social"></a>
- aleksacukovic1@gmail.com
