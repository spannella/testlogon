#!/usr/bin/env python3
"""DISP E2 prod fold — mirror the dev-clone E2 surfaces to PROD (i-08f937fc705ebea75) via SSM.

Verbatim files (dev pre-E2 == prod pre-E2, md5-confirmed):
  app/auth/roles.py                 (+ AdminScope.PAYMENT_DISPUTES)
  app/services/billing_disputes.py  (+ list_creator_disputes/creator_respond/admin_dispute_view/_rail_preview/_linked_incident)
  app/routers/billing_disputes.py   (creator endpoints + PAYMENT_DISPUTES gate + admin detail + dual-approval)

Anchor-patched files (prod diverges elsewhere; anchors md5-confirmed present):
  app/core/settings.py  (+ dispute_dual_approval_threshold_cents / _enabled)
  app/models.py         (+ CreatorDisputeRespondIn, DisputeResolveIn.second_approver_admin_user_id)

Backs up each touched file to .bak_disp_e2_<ts>, chowns ubuntu:ubuntu, restarts the backend
(root-uvicorn kill first), verifies openapi 200 + the new routes present.
"""
import base64, subprocess, sys, os, time

HERE = os.path.dirname(os.path.abspath(__file__))
SSM = "/tmp/ssm_send.py"

VERBATIM = {
    "app/auth/roles.py": "roles.py",
    "app/services/billing_disputes.py": "billing_disputes_service.py",
    "app/routers/billing_disputes.py": "billing_disputes_router.py",
}
PATCHERS = {
    "patch_settings.py": "patch_settings.py",
    "patch_models.py": "patch_models.py",
}


def b64(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def build_script():
    ts = str(int(time.time()))
    lines = [
        "set -e",
        "cd /home/ubuntu/testlogon",
        f'TS={ts}',
        'echo "PROD E2 fold @ $TS"',
    ]
    # verbatim files
    for dest, local in VERBATIM.items():
        payload = b64(os.path.join(HERE, local))
        lines.append(f'cp {dest} {dest}.bak_disp_e2_$TS')
        lines.append(f'echo "{payload}" | base64 -d > {dest}')
        lines.append(f'chown ubuntu:ubuntu {dest}')
    # patchers (write to /tmp on prod, back up target, run)
    for target, patcher in [("app/core/settings.py", "patch_settings.py"),
                            ("app/models.py", "patch_models.py")]:
        payload = b64(os.path.join(HERE, patcher))
        lines.append(f'cp {target} {target}.bak_disp_e2_$TS')
        lines.append(f'echo "{payload}" | base64 -d > /tmp/{patcher}')
        lines.append(f'python3 /tmp/{patcher}')
        lines.append(f'chown ubuntu:ubuntu {target}')
    # import sanity
    lines.append('sudo -u ubuntu bash -lc "cd /home/ubuntu/testlogon && set -a; . .env.local 2>/dev/null; . .venv/bin/activate 2>/dev/null; python3 -c \'import app.main; print(\\"import OK\\")\'"')
    # restart: kill root-owned uvicorn first, then ubuntu restart script
    lines.append('pkill -f "uvicorn app.main" || true')
    lines.append('sleep 3')
    lines.append('sudo -u ubuntu bash /home/ubuntu/restart_backend.sh || true')
    lines.append('sleep 6')
    lines.append('for i in $(seq 1 30); do c=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/openapi.json); [ "$c" = "200" ] && { echo "OPENAPI 200"; break; }; sleep 2; done')
    lines.append('curl -s http://localhost:8000/openapi.json | python3 -c \'import sys,json; d=json.load(sys.stdin); ps=[p for p in d["paths"] if "creator/disputes" in p or "admin/disputes/{dispute_id}"==p]; print("E2 ROUTES:", sorted(ps))\'')
    return "\n".join(lines)


def main():
    script = build_script()
    p = subprocess.run(["python3", SSM], input=script, capture_output=True, text=True)
    sys.stdout.write(p.stdout)
    if p.stderr.strip():
        sys.stderr.write(p.stderr)


if __name__ == "__main__":
    main()
