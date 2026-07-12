import time, json, traceback
def E(m): print('EVIDENCE| '+str(m), flush=True)
TS=int(time.time()); PW='TestLogon!2026'; R={}

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts
from boto3.dynamodb.conditions import Key

E('flags midroll_enabled=%s billing_enabled=%s min_interval=%s max_breaks=%s'%(
  S.broadcast_midroll_enabled, S.broadcast_ads_billing_enabled,
  getattr(S,'broadcast_midroll_min_interval_seconds',None),
  getattr(S,'broadcast_midroll_max_breaks_per_session',None)))

# ---- fresh users (sub == email in this dev backend, per seed_ad_demo) ----
from app.services.registration import create_user_record, mark_user_verified
def mkuser(email,name):
    try: create_user_record(email=email, full_name=name, password=PW, verification_required=False)
    except Exception as e: E('mkuser warn %s'%str(e)[:80])
    mark_user_verified(email); return email
ADVU=mkuser('adv.mid.%d@testlogon.example'%TS,'Mid Advertiser')
BRO =mkuser('bro.mid.%d@testlogon.example'%TS,'Mid Broadcaster')
VWR =mkuser('vwr.mid.%d@testlogon.example'%TS,'Mid Viewer')
SUBU=mkuser('sub.mid.%d@testlogon.example'%TS,'Mid Subscriber')
ADMIN='adv2e1_admin'
E('users adv=%s bro=%s vwr=%s sub=%s'%(ADVU,BRO,VWR,SUBU))

# ---- advertiser: account -> approve -> fund -> campaign -> creative ----
from app.models import AdAccountCreateIn, CampaignCreateIn, CreativeCreateIn
from app.services import ad_accounts, ad_campaigns, ad_creatives, ad_billing
acct=ad_accounts.create_ad_account(ADVU, AdAccountCreateIn(company_name='Acme Mid Ads', billing_email=ADVU))
AID=acct['account_id']; ad_accounts.review_ad_account(AID, ADMIN, 'approve')
try: ad_billing.deposit_funds(AID, 500000, '')
except Exception as e: E('deposit warn %s'%str(e)[:80])
E('ad_account=%s balance=%d'%(AID, ad_billing._get_balance(AID)))
camp=ad_campaigns.create_campaign(AID, CampaignCreateIn(name='Mid Launch', objective='awareness', budget_cents=1000000, budget_type='lifetime', bid_cpm_cents=20000, category='general'))
CID=camp['campaign_id']; ad_campaigns.submit_campaign_for_review(AID, CID); ad_campaigns.review_campaign(CID, ADMIN, 'approve')
cr=ad_creatives.create_creative(CID, AID, CreativeCreateIn(format='image', title='Acme Mid', headline='Mid roll hero', body_text='Coffee break.', cta_text='Learn more', cta_url='https://acme.coffee/learn', skip_after_seconds=5))
CRID=cr['creative_id']
T.ad_creatives.update_item(Key={'pk':cr['pk'],'sk':cr['sk']}, UpdateExpression='SET image_url=:u, skip_after_seconds=:s', ExpressionAttributeValues={':u':'https://images.unsplash.com/photo-1447933601403-0c6688de566e?w=1200&q=80', ':s':5})
ad_creatives.submit_creative_for_review(CID, CRID); ad_creatives.review_creative(CRID, ADMIN, 'approve')
E('campaign=%s creative=%s (approved)'%(CID, CRID))

# broadcaster allows ads
try:
    from app.services import creator_ad_prefs
    from app.models import CreatorAdSettingsIn
    creator_ad_prefs.update_creator_ad_settings(BRO, CreatorAdSettingsIn(allow_ads=True))
except Exception as e: E('allow_ads warn %s'%str(e)[:80])

# ---- broadcast session (live) ----
from app.services import broadcast_ads as ba
from app.services.broadcast_store import create_session, get_session, update_session_fields
sess=create_session(profile_id=BRO, created_by=BRO); SID=sess.id
update_session_fields(SID, {"status":"live","pre_roll_enabled":False,"mid_roll_ad_break_duration_seconds":30,"mid_roll_skip_after_seconds":15})
sess=get_session(SID)
ba.start_ad_break(sess); sess=get_session(SID)
R['break_active']=bool(sess.ad_break_active and sess.total_ad_breaks==1 and sess.last_ad_break_at)
E('break_active=%s total=%s last_at=%s remaining=%s'%(sess.ad_break_active, sess.total_ad_breaks, sess.last_ad_break_at, ba._break_remaining_seconds(sess)))

# ---- ADV2-101: per-viewer mid-roll serve ----
mv=ba.build_mid_roll(sess, VWR); mid=mv['mid_roll']; click=(mid or {}).get('ad_click_id','')
row=T.ad_clicks.get_item(Key={'ad_click_id':click}).get('Item') if click else None
WIN=(row or {}).get('account_id','')  # auction winner's ad account (prod has other bidders)
R['serve_creative']=bool(mid and click and row and row.get('surface')=='broadcast_midroll' and row.get('content_owner_sub')==BRO and WIN)
E('serve mid=%s click=%s surface=%s owner=%s win_acct=%s eff_price=%s remaining=%s'%(bool(mid), click[:12], row and row.get('surface'), row and row.get('content_owner_sub'), WIN, row and row.get('effective_price_cents'), mv.get('remaining_seconds')))

# ---- ADV2-102: completion charge (advertiser CPM + broadcaster 70/30 + idempotent) ----
def bro_credits():
    r=T.billing.query(KeyConditionExpression=Key('pk').eq(ad_billing.user_pk(BRO)))
    return [i for i in r.get('Items',[]) if i.get('type')=='credit' and (i.get('meta') or {}).get('surface')=='broadcast_midroll']
win_bal0=ad_billing._get_balance(WIN); c0=sum(int(i['amount_cents']) for i in bro_credits())
ba.record_ad_event(session_id=SID, creative_id=mid['creative_id'], user_id=VWR, event_type='impression', slot_type='broadcast_midroll', ad_click_id=click, view_time_ms=9000)
win_bal1=ad_billing._get_balance(WIN); c1=sum(int(i['amount_cents']) for i in bro_credits())
charge=win_bal0-win_bal1; credit=c1-c0
R['advertiser_debited']=charge>0
R['broadcaster_credited_70']=(credit>0 and credit==(charge*7000)//10000)
R['platform_30']=((charge-credit)==charge-(charge*7000)//10000) and (charge-credit)>0
E('charge: adv_debit=%d broadcaster_credit_70=%d platform_30=%d'%(charge, credit, charge-credit))
# idempotency: repeat complete + impression = 0 extra
ba.record_ad_event(session_id=SID, creative_id=mid['creative_id'], user_id=VWR, event_type='complete', slot_type='broadcast_midroll', ad_click_id=click, view_time_ms=30000)
ba.record_ad_event(session_id=SID, creative_id=mid['creative_id'], user_id=VWR, event_type='impression', slot_type='broadcast_midroll', ad_click_id=click, view_time_ms=9000)
win_bal2=ad_billing._get_balance(WIN); c2=sum(int(i['amount_cents']) for i in bro_credits())
R['idempotent']=(win_bal2==win_bal1 and c2==c1)
E('idempotent extra_debit=%d extra_credit=%d (want 0/0)'%(win_bal1-win_bal2, c2-c1))
# idempotency key label on the ad_clicks row
crow=T.ad_clicks.get_item(Key={'ad_click_id':click}).get('Item') or {}
E('ad_click status=%s charged_cents=%s'%(crow.get('status'), crow.get('charged_cents')))

# ---- self broadcaster + ad-free subscriber: no serve ----
mvb=ba.build_mid_roll(sess, BRO)
R['self_broadcaster_no_serve']=(mvb['mid_roll'] is None and mvb['ad_free'] is True)
from app.services.subscription_access import _pk_subscriber, has_active_subscription
T.subscriptions.put_item(Item={'pk':_pk_subscriber(SUBU),'sk':'SUB#'+BRO,'creator_id':BRO,'status':'active','created_at':now_ts()})
R['sub_is_adfree']=has_active_subscription(SUBU,BRO)
mvs=ba.build_mid_roll(sess, SUBU)
R['adfree_sub_no_serve']=(mvs['mid_roll'] is None and mvs['ad_free'] is True)
E('self_no_serve=%s sub_adfree=%s adfree_sub_no_serve=%s'%(R['self_broadcaster_no_serve'], R['sub_is_adfree'], R['adfree_sub_no_serve']))

# ---- ADV2-104 guardrails + ADV2-103 state via TestClient ----
from fastapi.testclient import TestClient
import app.main as m
from app.services.sessions import require_ui_session
client=TestClient(m.app)
m.app.dependency_overrides[require_ui_session]=lambda:{"user_sub":BRO,"role":"creator"}
# too soon: recent last break, not active, total 1
s2=create_session(profile_id=BRO, created_by=BRO); update_session_fields(s2.id, {"status":"live","ad_break_active":False,"total_ad_breaks":1,"last_ad_break_at":now_ts()})
r=client.post('/broadcast/sessions/%s/ad-break'%s2.id); j=r.json()
R['guard_too_soon']=(r.status_code==429 and (j.get('detail') or {}).get('code')=='AD_BREAK_TOO_SOON')
E('too_soon status=%s body=%s'%(r.status_code, r.text[:180]))
# max breaks: total 4, last break old
s3=create_session(profile_id=BRO, created_by=BRO); update_session_fields(s3.id, {"status":"live","ad_break_active":False,"total_ad_breaks":4,"last_ad_break_at":now_ts()-100000})
r=client.post('/broadcast/sessions/%s/ad-break'%s3.id); j=r.json()
R['guard_max_breaks']=(r.status_code==429 and (j.get('detail') or {}).get('code')=='MAX_BREAKS_REACHED')
E('max_breaks status=%s body=%s'%(r.status_code, r.text[:180]))
# legit first trigger + state
s4=create_session(profile_id=BRO, created_by=BRO); update_session_fields(s4.id, {"status":"live"})
r=client.post('/broadcast/sessions/%s/ad-break'%s4.id)
R['guard_first_ok']=(r.status_code==200)
E('first_trigger status=%s body=%s'%(r.status_code, r.text[:180]))
r=client.get('/broadcast/sessions/%s/ad-break/state'%s4.id); sj=r.json()
R['state_route']=(r.status_code==200 and sj.get('ad_break_active') is True and 'remaining_seconds' in sj)
E('state status=%s body=%s'%(r.status_code, r.text[:200]))
# serve route as viewer on the active break
m.app.dependency_overrides[require_ui_session]=lambda:{"user_sub":VWR,"role":"viewer"}
r=client.post('/broadcast/sessions/%s/ad-break/serve'%s4.id); sj=r.json()
R['serve_route']=(r.status_code==200 and bool(sj.get('mid_roll')) and bool((sj.get('mid_roll') or {}).get('ad_click_id')))
E('serve_route status=%s mid_roll=%s remaining=%s'%(r.status_code, bool(sj.get('mid_roll')), sj.get('remaining_seconds')))
m.app.dependency_overrides.clear()

keys=['break_active','serve_creative','advertiser_debited','broadcaster_credited_70','platform_30','idempotent','self_broadcaster_no_serve','sub_is_adfree','adfree_sub_no_serve','guard_too_soon','guard_max_breaks','guard_first_ok','state_route','serve_route']
for k in keys: E('CHECK %-26s = %s'%(k, R.get(k)))
E('OVERALL '+('ALL_PASS' if all(R.get(k) for k in keys) else 'SOME_FAIL'))
