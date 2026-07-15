import base64, time, sys
patch_b64 = base64.b64encode(open("/tmp/subx4_server.patch", "rb").read()).decode()
ts = int(time.time())
script = f"""set -e
cd /home/ubuntu/testlogon
cat > /tmp/subx4_server.patch.b64 <<'B64EOF'
{patch_b64}
B64EOF
base64 -d /tmp/subx4_server.patch.b64 > /tmp/subx4_server.patch
BAK="app/routers/subscription_server.py.bak_subx_{ts}"
sudo -u ubuntu cp app/routers/subscription_server.py "$BAK"
echo "BACKUP $BAK"
sudo -u ubuntu patch -p1 --forward < /tmp/subx4_server.patch
sudo -u ubuntu python3 -c 'import ast; ast.parse(open("app/routers/subscription_server.py").read()); print("AST_OK")'
sudo chown ubuntu:ubuntu app/routers/subscription_server.py
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh
sleep 6
echo "OPENAPI $(curl -s -o /dev/null -w '%{{http_code}}' http://localhost:8000/openapi.json)"
echo "HAS_REORDER $(curl -s http://localhost:8000/openapi.json | grep -c 'plans/reorder')"
echo "HAS_BYTIER $(curl -s http://localhost:8000/openapi.json | grep -c 'by_tier')"
"""
open("/tmp/subx4_ssm.sh", "w").write(script)
print("wrote /tmp/subx4_ssm.sh bak_ts={}".format(ts))
