import time, json
from app.core.tables import T
from boto3.dynamodb.conditions import Key
from app.services import ad_accounts, ad_campaigns, ad_creatives, ad_billing, ad_serving, vod_ad_supported
from app.models import AdAccountCreateIn, CampaignCreateIn, CreativeCreateIn, CampaignUpdateIn
from app.services import creator_earnings as CE
from app.services.creator_payouts import get_available_balance
from app.services.creator_ad_prefs import get_creator_ad_settings

TS = int(time.time())
U1 = 'e2e_u1_adv_%d' % TS      # advertiser (also self-exclusion viewer)
U2 = 'e2e_u2_creator_%d' % TS  # creator / video poster
U3 = 'e2e_u3_viewer_%d' % TS   # viewer
ADMIN = 'e2e_admin_reviewer'
VIDEO_ID = 'e2e_vid_%d' % TS
R = {}

def acct_bal(a): return ad_billing._get_balance(a)
def gross(u): return CE.get_earnings_summary(u)['total_cents']

print('=== STEP 1: U1 advertiser create -> approve -> fund -> campaign -> creative -> approve ===')
acct = ad_accounts.create_ad_account(U1, AdAccountCreateIn(company_name='E2E Ads Co', billing_email='u1@e2e.test'))
AID = acct['account_id']
print('account', AID, 'status', acct.get('status'))
ad_accounts.review_ad_account(AID, ADMIN, 'approve')
print('approved ->', ad_accounts.get_ad_account(AID).get('status'))
try:
    dep = ad_billing.deposit_funds(AID, 100000, payment_method_id='pm_e2e_card')
    print('deposit(card) ->', dep, 'path=card')
except Exception as e:
    dep = ad_billing.deposit_funds(AID, 100000, payment_method_id='')
    print('deposit(dev-stub) ->', dep, 'path=stub (card 402:', str(e)[:60], ')')
R['u1_balance_after_fund'] = acct_bal(AID)
print('balance after fund =', R['u1_balance_after_fund'])
camp = ad_campaigns.create_campaign(AID, CampaignCreateIn(name='E2E Camp', objective='awareness', budget_cents=500000, budget_type='lifetime', bid_cpm_cents=20000, category='general'))
CID = camp['campaign_id']
ad_campaigns.update_campaign(AID, CID, CampaignUpdateIn(status='pending_review'))
ad_campaigns.update_campaign(AID, CID, CampaignUpdateIn(status='active'))
print('campaign', CID, 'status', ad_campaigns.get_campaign(AID, CID).get('status'), 'bid_cpm', ad_campaigns.get_campaign(AID, CID).get('bid_cpm_cents'))
cr = ad_creatives.create_creative(CID, AID, CreativeCreateIn(format='image', title='E2E Creative', cta_text='Buy', cta_url='https://e2e.test/x'))
CRID = cr['creative_id']
T.ad_creatives.update_item(Key={'pk': cr['pk'], 'sk': cr['sk']}, UpdateExpression='SET image_url=:u', ExpressionAttributeValues={':u': 'http://localhost:8000/mock/s3/creatives/e2e.png'})
ad_creatives.review_creative(CRID, ADMIN, 'approve')
print('creative', CRID, 'status', ad_creatives.get_creative(CID, CRID).get('status'))

print('=== STEP 2: U2 creator enables ads (allow_ads opt-in) ===')
from app.services import creator_ad_prefs
from app.models import CreatorAdSettingsIn
done = False
try:
    creator_ad_prefs.update_creator_ad_settings(U2, CreatorAdSettingsIn(allow_ads=True))
    done = True
    print('enabled ads via update_creator_ad_settings(CreatorAdSettingsIn)')
except Exception as e:
    print('enable warn:', str(e)[:120])
print('U2 allow_ads =', get_creator_ad_settings(U2).get('allow_ads', True), 'done=', done)
u2_gross_before = gross(U2)
print('U2 gross earnings before =', u2_gross_before)

print('=== STEP 3: U3 views U2 video -> preroll serve (U1 creative) -> completion charge+credit ===')
served = ad_serving.serve_ad(surface='preroll', content_type='vod', creator_id=U2, content_id=VIDEO_ID, slot_type='pre_roll', user_id=U3, content_owner_id=U2)
print('serve_ad(U3) filled=', served.get('filled'), 'is_house=', served.get('is_house_ad'), 'creative=', served.get('creative_id'), 'account=', served.get('account_id'), 'ad_click_id=', served.get('ad_click_id'))
R['u3_served_our_creative'] = bool(served.get('filled') and not served.get('is_house_ad') and served.get('account_id') == AID and served.get('creative_id') == CRID)
ACK = served.get('ad_click_id')
click_row = T.ad_clicks.get_item(Key={'ad_click_id': ACK}).get('Item') if ACK else {}
print('AdClicks row: surface=', click_row.get('surface'), 'content_owner_sub=', click_row.get('content_owner_sub'), 'effective_price_cents=', click_row.get('effective_price_cents'), 'viewer_sub=', click_row.get('viewer_sub'))
bal_before = acct_bal(AID)
res = vod_ad_supported._charge_preroll_completion(target={'ad_click_id': ACK, 'creative_id': CRID}, video_id=VIDEO_ID)
bal_after = acct_bal(AID)
u2_gross_after = gross(U2)
click_after = T.ad_clicks.get_item(Key={'ad_click_id': ACK}).get('Item')
print('charge result ok=', res.get('ok'), 'charge_cents=', res.get('charge_cents'))
print('U1 balance', bal_before, '->', bal_after, 'delta=', bal_before - bal_after)
print('U2 gross', u2_gross_before, '->', u2_gross_after, 'delta(poster credit)=', u2_gross_after - u2_gross_before)
print('AdClicks after: status=', click_after.get('status'), 'charged_cents=', click_after.get('charged_cents'), 'content_owner=', click_after.get('content_owner_sub'))
charge_cents = int(res.get('charge_cents', 0) or 0)
R['u1_charged'] = bool(res.get('ok') and (bal_before - bal_after) == charge_cents and charge_cents > 0)
R['u2_credited'] = (u2_gross_after - u2_gross_before) > 0
res2 = vod_ad_supported._charge_preroll_completion(target={'ad_click_id': ACK, 'creative_id': CRID}, video_id=VIDEO_ID)
bal_after2 = acct_bal(AID)
print('repeat charge ok=', res2.get('ok'), 'charge_cents=', res2.get('charge_cents'), 'balance stayed', bal_after == bal_after2)
R['idempotent'] = (bal_after == bal_after2)

print('=== STEP 4: SELF-EXCLUSION: U1 views a video -> must NOT be served own campaign ===')
served_self = ad_serving.serve_ad(surface='preroll', content_type='vod', creator_id=U2, content_id=VIDEO_ID + '_b', slot_type='pre_roll', user_id=U1, content_owner_id=U2)
print('serve_ad(U1 self) filled=', served_self.get('filled'), 'is_house=', served_self.get('is_house_ad'), 'reason=', served_self.get('reason'), 'account=', served_self.get('account_id'), 'creative=', served_self.get('creative_id'))
R['self_excluded'] = (served_self.get('account_id') != AID and served_self.get('creative_id') != CRID)
self_ack = served_self.get('ad_click_id')
self_click = T.ad_clicks.get_item(Key={'ad_click_id': self_ack}).get('Item') if self_ack else None
if self_click:
    print('self serve click account=', self_click.get('account_id'), '(must != ', AID, ')')
    R['self_no_own_charge'] = self_click.get('account_id') != AID
else:
    R['self_no_own_charge'] = True

print('=== RESULTS ===')
keys = ['u1_charged', 'u2_credited', 'idempotent', 'u3_served_our_creative', 'self_excluded', 'self_no_own_charge']
for k in keys:
    print('  %s =' % k, R.get(k))
allok = all(R.get(k) for k in keys)
print('MATRIX:', json.dumps({'U1_account': AID, 'campaign': CID, 'creative': CRID, 'ad_click_id': ACK, 'charge_cents': charge_cents, 'u2_poster_credit': u2_gross_after - u2_gross_before, 'video': VIDEO_ID}))
print('OVERALL', 'PASS' if allok else 'FAIL')
