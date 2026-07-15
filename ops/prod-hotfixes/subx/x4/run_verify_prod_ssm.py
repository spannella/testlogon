import base64
v_b64 = base64.b64encode(open("/home/sean/dev/testlogon/ops/prod-hotfixes/subx/x4/verify_subx4.py", "rb").read()).decode()
script = f"""set -e
cd /home/ubuntu/testlogon
cat > /tmp/verify_subx4.py.b64 <<'B64EOF'
{v_b64}
B64EOF
base64 -d /tmp/verify_subx4.py.b64 > /tmp/verify_subx4.py
cat > /tmp/run_verify_subx4.sh <<'RUNEOF'
cd /home/ubuntu/testlogon
source .venv/bin/activate
set -a; source .env.local; set +a
export PYTHONPATH=/home/ubuntu/testlogon
python /tmp/verify_subx4.py 2>&1 | grep -E 'PASS|FAIL|VERIFY|CLEANUP|RAISED' | tail -30
RUNEOF
bash /tmp/run_verify_subx4.sh
rm -f /tmp/verify_subx4.py /tmp/verify_subx4.py.b64 /tmp/run_verify_subx4.sh
"""
open("/tmp/subx4_verify_ssm.sh", "w").write(script)
print("wrote /tmp/subx4_verify_ssm.sh")
