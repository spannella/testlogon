import sys; sys.path.insert(0,"/home/ubuntu/testlogon")
import time
from app.services import shipment_tracking as st
from app.services import easypost_client as ep
from app.core.settings import S

R=[]
def ck(n,c): R.append((n,c)); print(('PASS' if c else 'FAIL'),n)

SG='sg_ep_verify_%d'%int(time.time())
TN='1Z999AA1%010d'%(int(time.time())%10**10)  # UPS-shaped

# capture pushes
pushes=[]
_orig=st._notify_buyer
st._notify_buyer=lambda rec,ev,ti: pushes.append((ev,rec.get('status')))
try:
    # 1. NO-KEY create_on_ship unchanged
    ck('key absent', not ep.is_enabled())
    rec=st.create_on_ship({'ship_group_id':SG,'tracking_number':TN,'buyer_id':'buyer_ep','order_id':'ord_ep','line_items':[{'name':'Verify Widget'}]})
    ck('create_on_ship label_created', rec and rec.get('status')=='label_created')
    ck('no easypost_tracker_id (no key)', 'easypost_tracker_id' not in (rec or {}))
    ck('carrier detected UPS', rec.get('carrier')=='UPS')

    # 2. EasyPost webhook parse -> advance -> push (in_transit, out_for_delivery, delivered)
    def ev(status):
        return {'object':'Event','description':'tracker.updated','result':{
            'id':'trk_ver1','object':'Tracker','tracking_code':TN,'status':status,'carrier':'UPS',
            'tracking_details':[
              {'object':'TrackingDetail','message':'Label','status':'pre_transit','tracking_location':{'city':None,'state':None,'zip':None}},
              {'object':'TrackingDetail','message':'Scan '+status,'status':status,'tracking_location':{'city':'MEMPHIS','state':'TN','zip':'38118'}}]}}
    r=st.ingest_webhook(ev('in_transit'))
    ck('ep webhook in_transit', r.get('ok') and r.get('provider')=='easypost' and r.get('status')=='in_transit')
    r=st.ingest_webhook(ev('out_for_delivery'))
    ck('ep webhook out_for_delivery', r.get('status')=='out_for_delivery')
    ck('push order_out_for_delivery fired', ('order_out_for_delivery','out_for_delivery') in pushes)
    r=st.ingest_webhook(ev('delivered'))
    ck('ep webhook delivered', r.get('status')=='delivered')
    ck('push order_delivered fired', ('order_delivered','delivered') in pushes)
    # idempotent replay
    before=list(pushes); st.ingest_webhook(ev('delivered'))
    ck('delivered push idempotent', pushes==before)

    # 3. create_on_ship WOULD call EasyPost when keyed (dry-run, mocked create_tracker, NO real HTTP)
    called={}
    st_ep=ep
    orig_en=ep.is_enabled; orig_ct=ep.create_tracker
    ep.is_enabled=lambda: True
    ep.create_tracker=lambda tracking_code,carrier=None,**k: (called.update(tc=tracking_code,carrier=carrier) or {'ok':True,'id':'trk_DRYRUN','status':'pre_transit','carrier':'UPS'})
    try:
        SG2=SG+'_keyed'
        rec2=st.create_on_ship({'ship_group_id':SG2,'tracking_number':TN,'buyer_id':'b','order_id':'o','line_items':[{'name':'X'}]})
        ck('keyed: create_tracker called w/ code+carrier', called.get('tc')==TN and called.get('carrier')=='UPS')
        ck('keyed: easypost_tracker_id stored', rec2.get('easypost_tracker_id')=='trk_DRYRUN')
        ck('keyed: provider=easypost', rec2.get('tracking_provider')=='easypost')
    finally:
        ep.is_enabled=orig_en; ep.create_tracker=orig_ct
        try: st._table().delete_item(Key={'ship_group_id':SG2})
        except Exception: pass

    # 4. status map spot-check
    ck('map return_to_sender->exception', ep.map_status('return_to_sender')=='exception')
    ck('map available_for_pickup->in_transit', ep.map_status('available_for_pickup')=='in_transit')
finally:
    st._notify_buyer=_orig
    try: st._table().delete_item(Key={'ship_group_id':SG})
    except Exception: pass

print('OVERALL', 'ALL_PASS' if all(c for _,c in R) else 'FAIL', '%d/%d'%(sum(1 for _,c in R if c),len(R)))
