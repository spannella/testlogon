import os, sys, base64, hashlib, time
sys.path.insert(0, "/home/ubuntu/testlogon")
os.chdir("/home/ubuntu/testlogon")
import requests
from app.core.tables import T
from app.core.normalize import normalize_email

BASE="http://localhost:8000"
USER="webfix_prod_probe@example.com"; PW="Pr0dSecret!pw"
sub=normalize_email(USER)
def make_ph(pw):
    salt=os.urandom(16); it=200000
    h=hashlib.pbkdf2_hmac("sha256",pw.encode(),salt,it)
    return {"hash_b64":base64.b64encode(h).decode(),"salt_b64":base64.b64encode(salt).decode(),"iterations":it}
T.users.put_item(Item={"user_sub":sub,"email":USER,"role":"admin","password_hash":make_ph(PW),"created_at":int(time.time()),
    "admin_profile":{"type":"scoped","scopes":["content_moderation","content_moderation_senior"]}})
s=requests.Session()
r=s.post(f"{BASE}/ui/session/start",json={"challenge_context":{"username":USER,"password":PW}})
print("start:",r.status_code, r.text[:120])
print("me:",s.get(f"{BASE}/ui/me").text[:400])
print("orders:",s.get(f"{BASE}/ui/orders",params={"limit":50}).status_code, s.get(f"{BASE}/ui/orders",params={"limit":50}).text[:200])
T.users.delete_item(Key={"user_sub":sub})
print("cleanup deleted", sub)
