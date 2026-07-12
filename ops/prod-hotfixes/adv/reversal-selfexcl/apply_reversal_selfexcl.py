import io, sys, re

CE = 'app/services/creator_earnings.py'
AD = 'app/services/ad_serving.py'
root = sys.argv[1] if len(sys.argv) > 1 else '.'
import os
ce = os.path.join(root, CE)
ad = os.path.join(root, AD)

changed = []

# ---- FIX 1: creator_earnings, both filter_expr lines ----
s = open(ce, encoding='utf-8').read()
old = '    filter_expr = Attr("type").eq("credit")\n'
new = ('    # FIX (reversal true-up): exclude reversed credits from GROSS earnings too so a\n'
       '    # reversed tip/ad credit drops out of the dashboard total (mirrors get_available_balance;\n'
       '    # Attr("state").ne("reversed") is True on legacy rows with no state attr -> back-compat).\n'
       '    filter_expr = Attr("type").eq("credit") & Attr("state").ne("reversed")\n')
n = s.count(old)
if n == 0 and 'Attr("state").ne("reversed")' in s:
    changed.append('FIX1: already applied (skip)')
else:
    s2 = s.replace(old, new)
    assert s2.count('Attr("state").ne("reversed")') >= n, "FIX1 count mismatch"
    open(ce,'w',encoding='utf-8').write(s2)
    changed.append(f'FIX1: patched {n} filter_expr site(s)')

# ---- FIX 3: ad_serving self-exclusion ----
s = open(ad, encoding='utf-8').read()
if 'Self-ad exclusion' in s:
    changed.append('FIX3: already applied (skip)')
else:
    anchor = '        account_id = campaign["account_id"]\n'
    assert s.count(anchor) == 1, f'FIX3 anchor count={s.count(anchor)}'
    block = anchor + (
        '\n'
        '        # Self-ad exclusion (money-path safety): never serve an advertiser their\n'
        '        # OWN campaign. The viewer must not be shown, charged for, or credited by an\n'
        '        # ad from an account they own. Skip when the ad-account owner == viewer.\n'
        '        try:\n'
        '            from app.services.ad_accounts import get_ad_account\n'
        '            _acct = get_ad_account(account_id)\n'
        '            if _acct and str(_acct.get("owner_sub", "") or "") == str(user_id or ""):\n'
        '                continue\n'
        '        except Exception:\n'
        '            pass\n'
    )
    s2 = s.replace(anchor, block)
    open(ad,'w',encoding='utf-8').write(s2)
    changed.append('FIX3: inserted self-exclusion block')

print('\n'.join(changed))
