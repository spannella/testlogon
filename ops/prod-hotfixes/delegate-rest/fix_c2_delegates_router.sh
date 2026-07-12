set -e
cd /home/ubuntu/testlogon
TS=$(date +%s)
cp app/routers/delegates.py app/routers/delegates.py.bak_delegc2_$TS
echo "BAK_TS=$TS"
python3 - <<'PY'
p='app/routers/delegates.py'
s=open(p).read()
old='''def _to_managed_creator(item: dict) -> ManagedCreatorOut:
    return ManagedCreatorOut(
        creator_id=item.get("creator_id", ""),
        permissions=item.get("permissions", []),
        preset=item.get("preset"),
        status=item.get("status", ""),
        label=item.get("label", ""),
        accepted_at=int(item.get("accepted_at", 0)),
    )'''
new='''def _to_managed_creator(item: dict) -> ManagedCreatorOut:
    # DELEGATE-REST cosmetic C2: the "managed creators" list is the set of
    # CREATORS the principal manages, so the human label must be the CREATOR's
    # name (not the delegate-relationship label). Resolve the creator's profile
    # display name; fall back to the stored delegate label, then the id. The
    # app maps this `label` -> DelegationContext.creatorName -> the banner
    # ("Managing <Creator>"), so this fixes the banner with no client change.
    creator_id = item.get("creator_id", "")
    creator_name = ""
    try:
        from app.services.profile import get_profile
        prof = get_profile(creator_id) or {}
        creator_name = (prof.get("display_name") or prof.get("username") or "").strip()
    except Exception:
        creator_name = ""
    return ManagedCreatorOut(
        creator_id=creator_id,
        permissions=item.get("permissions", []),
        preset=item.get("preset"),
        status=item.get("status", ""),
        label=creator_name or item.get("label", "") or creator_id,
        accepted_at=int(item.get("accepted_at", 0)),
    )'''
assert s.count(old)==1, ('c2 anchor', s.count(old))
s=s.replace(old,new,1)
open(p,'w').write(s)
import py_compile; py_compile.compile(p, doraise=True)
print("C2_PATCH_OK")
PY
