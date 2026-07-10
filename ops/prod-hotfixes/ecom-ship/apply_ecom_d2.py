import sys
TS=sys.argv[1]
mp='app/models.py'
s=open(mp).read()
old='class AlertPushPrefsReq(BaseModel):\n    push_event_types: List[str] = Field(default_factory=list)\n'
new=('class AlertPushPrefsReq(BaseModel):\n'
     '    # D2: push-pref toggle. push_event_types = explicit opt-IN list; push_opt_out_event_types =\n'
     '    # opt-OUT of the default-ON transactional events. Both optional so a partial update keeps the\n'
     '    # unspecified list unchanged (None -> set_alert_prefs preserves current).\n'
     '    push_event_types: Optional[List[str]] = None\n'
     '    push_opt_out_event_types: Optional[List[str]] = None\n')
if 'push_opt_out_event_types: Optional[List[str]] = None' in s:
    print('models already patched')
else:
    assert s.count(old)==1, ('models anchor',s.count(old))
    open(mp+'.bak_ecomd2_'+TS,'w').write(s)
    open(mp,'w').write(s.replace(old,new)); print('models.py patched')

rp='app/routers/alerts.py'
s=open(rp).read()
if 'async def get_push_prefs(' in s:
    print('router already patched')
else:
    open(rp+'.bak_ecomd2_'+TS,'w').write(s)
    imp_old='from app.services.alerts import (\n    ALERT_EVENT_TYPES,\n'
    imp_new='from app.services.alerts import (\n    ALERT_EVENT_TYPES,\n    DEFAULT_PUSH_EVENT_TYPES,\n'
    assert s.count(imp_old)==1, ('import anchor',s.count(imp_old)); s=s.replace(imp_old,imp_new)
    post_old=('@router.post("/alerts/push_prefs")\n'
     'async def set_push_prefs(body: AlertPushPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):\n'
     '    prefs = set_alert_prefs(ctx["user_sub"], push_event_types=body.push_event_types)\n'
     '    audit_event("alerts_push_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("push_event_types") or []))\n'
     '    return prefs\n')
    post_new=('@router.get("/alerts/push_prefs")\n'
     'async def get_push_prefs(ctx: Dict[str, str] = Depends(require_ui_session)):\n'
     '    prefs = get_alert_prefs(ctx["user_sub"])\n'
     '    return {\n'
     '        "push_event_types": prefs.get("push_event_types", []),\n'
     '        "push_opt_out_event_types": prefs.get("push_opt_out_event_types", []),\n'
     '        "default_push_event_types": list(DEFAULT_PUSH_EVENT_TYPES),\n'
     '    }\n\n\n'
     '@router.post("/alerts/push_prefs")\n'
     'async def set_push_prefs(body: AlertPushPrefsReq, ctx: Dict[str, str] = Depends(require_ui_session)):\n'
     '    prefs = set_alert_prefs(\n'
     '        ctx["user_sub"],\n'
     '        push_event_types=body.push_event_types,\n'
     '        push_opt_out_event_types=body.push_opt_out_event_types,\n'
     '    )\n'
     '    audit_event("alerts_push_prefs_set", ctx["user_sub"], None, outcome="success", enabled=len(prefs.get("push_event_types") or []))\n'
     '    return prefs\n')
    assert s.count(post_old)==1, ('post anchor',s.count(post_old)); s=s.replace(post_old,post_new)
    open(rp,'w').write(s); print('routers/alerts.py patched')
