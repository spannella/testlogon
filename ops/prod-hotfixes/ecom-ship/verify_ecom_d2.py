import time
from app.core.tables import T
from app.services.alerts import get_alert_prefs, set_alert_prefs, DEFAULT_PUSH_EVENT_TYPES
u='d2test_'+str(int(time.time()))
p=get_alert_prefs(u)
print('default push_event_types',p['push_event_types'],'opt_out',p['push_opt_out_event_types'])
assert 'order_shipped' in DEFAULT_PUSH_EVENT_TYPES
p2=set_alert_prefs(u, push_opt_out_event_types=['order_shipped'])
print('after opt-out',p2['push_opt_out_event_types'])
assert p2['push_opt_out_event_types']==['order_shipped']
p3=set_alert_prefs(u, push_opt_out_event_types=[])
assert p3['push_opt_out_event_types']==[]
p4=set_alert_prefs(u, push_event_types=['comment_reply'])
assert 'comment_reply' in p4['push_event_types']
# opt_out only keeps default-on events (garbage filtered)
p5=set_alert_prefs(u, push_opt_out_event_types=['comment_reply'])
print('opt_out filters non-default', p5['push_opt_out_event_types'])
assert p5['push_opt_out_event_types']==[]
try: T.alert_prefs.delete_item(Key={'user_sub':u})
except Exception as e: print('cleanup',e)
print('D2_VERIFY_OK')
