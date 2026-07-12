#!/usr/bin/env python3
"""ADV2-E5 ad-message HYDRATION hotfix (idempotent, marker-guarded).

The delivered sponsored DM row already stores ad_message/ad_click_id/cta_url/
sponsor_label/content_owner_sub/ad_image_url (ad_messaging._send_message), but the
message READ-path serializer (_message_out_from_item -> MessageOut, which also
feeds the realtime event via _serialize_message_event_payload) dropped them. So a
real recipient device never saw the sponsor footer and could not fire the
open(+5c)/click(+10c) money beacons. This adds the fields to MessageOut + the
serializer so BOTH conversation history and the message:new event carry them.
Mirrors the TIP-B2 tip_reactions hydration. ROOT env selects the tree.
"""
import os, sys, py_compile

ROOT = os.environ.get('ROOT', '.')
PATH = os.path.join(ROOT, 'app/routers/messaging.py')
MARKER = '# ADV2-E5 ad-message hydration'

MODEL_ANCHOR = "    tip_reactions: list = []  # TIP-B2: money-reaction badges (author-side chip hydration)\n"
MODEL_ADD = (
    "    tip_reactions: list = []  # TIP-B2: money-reaction badges (author-side chip hydration)\n"
    "    ad_message: Optional[bool] = None  # ADV2-E5 ad-message hydration\n"
    "    ad_click_id: Optional[str] = None\n"
    "    cta_url: Optional[str] = None\n"
    "    ad_image_url: Optional[str] = None\n"
    "    sponsor_label: Optional[str] = None\n"
    "    content_owner_sub: Optional[str] = None\n"
)

SER_ANCHOR = (
    '            for _r in (merged_item.get("tip_reactions") or [])\n'
    '        ],\n'
    '        expires_at=int(merged_item["expires_at"]) if merged_item.get("expires_at") else None,\n'
)
SER_ADD = (
    '            for _r in (merged_item.get("tip_reactions") or [])\n'
    '        ],\n'
    '        ad_message=True if merged_item.get("ad_message") else None,  # ADV2-E5 ad-message hydration\n'
    '        ad_click_id=merged_item.get("ad_click_id") or None,\n'
    '        cta_url=merged_item.get("cta_url") or None,\n'
    '        ad_image_url=merged_item.get("ad_image_url") or None,\n'
    '        sponsor_label=merged_item.get("sponsor_label") or None,\n'
    '        content_owner_sub=merged_item.get("content_owner_sub") or None,\n'
    '        expires_at=int(merged_item["expires_at"]) if merged_item.get("expires_at") else None,\n'
)

s = open(PATH).read()
if MARKER in s:
    print('HYDRATE_SKIPPED_ALREADY_PRESENT')
    py_compile.compile(PATH, doraise=True); print('PYCOMPILE_OK'); sys.exit(0)

for name, anchor in [('MODEL', MODEL_ANCHOR), ('SERIALIZER', SER_ANCHOR)]:
    if anchor not in s:
        print('ANCHOR_MISSING', name); sys.exit(2)

s = s.replace(MODEL_ANCHOR, MODEL_ADD, 1)
s = s.replace(SER_ANCHOR, SER_ADD, 1)
open(PATH, 'w').write(s)
py_compile.compile(PATH, doraise=True)
print('HYDRATE_APPLIED PYCOMPILE_OK')
