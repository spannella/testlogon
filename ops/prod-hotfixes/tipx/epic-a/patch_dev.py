#!/usr/bin/env python3
"""TIPX-A dev-clone patcher (content-based, idempotent). Run from repo root."""
import io, sys, re

def read(p):
    with io.open(p, encoding="utf-8") as f: return f.read()
def write(p, s):
    with io.open(p, "w", encoding="utf-8") as f: f.write(s)

changed = []

def sub_once(path, old, new, label):
    s = read(path)
    if new in s and old not in s:
        print(f"  [skip] {label} (already applied)"); return
    n = s.count(old)
    if n != 1:
        print(f"  [FAIL] {label}: expected 1 occurrence of anchor, found {n}"); sys.exit(2)
    write(path, s.replace(old, new, 1))
    changed.append(label); print(f"  [ok]   {label}")

# ---------------------------------------------------------------------------
# A4 source-thread: pass source="tip" into write_collaboration_split_ledger
# ---------------------------------------------------------------------------
CR = "app/services/collaboration_revenue.py"
sub_once(CR,
    "    credited = write_collaboration_split_ledger(\n"
    "        collaboration_id=collaboration_id,\n"
    "        payer_user_id=payer_user_id,\n"
    "        amount_cents=amount_cents,\n"
    "        currency=currency,\n"
    "        content_type=resolved_type,\n"
    "        content_id=content_id,\n"
    "    )",
    "    credited = write_collaboration_split_ledger(\n"
    "        collaboration_id=collaboration_id,\n"
    "        payer_user_id=payer_user_id,\n"
    "        amount_cents=amount_cents,\n"
    "        currency=currency,\n"
    "        content_type=resolved_type,\n"
    "        content_id=content_id,\n"
    "        source=source,\n"
    "    )",
    "A4: thread source into split ledger")

# ---------------------------------------------------------------------------
# A3 idempotency: stable client_request_id-aware keys on the 6 fresh surfaces.
# The helper _stable_tip_idem builds "{surface}:{content}:{crid-or-stable}".
# ---------------------------------------------------------------------------
NF = "app/routers/newsfeed.py"

# Insert the stable-key helper right after new_id() in newsfeed.
helper = (
    "def new_id(prefix: str) -> str:\n"
    "    return f\"{prefix}_{uuid.uuid4().hex}\"\n"
)
helper_new = helper + (
    "\n\n"
    "def _stable_tip_idem(surface: str, tipper_id: str, content_id: str, client_request_id):\n"
    "    \"\"\"TIPX-A3: deterministic tip idempotency key.\n\n"
    "    When the client supplies a stable ``client_request_id`` the key is\n"
    "    ``{surface}:{content_id}:{crid}`` so a transparent retry of the SAME tip\n"
    "    action replays the stored receipt (charged once). Absent a client id we\n"
    "    fall back to a per-request-unique key (prior behavior) so distinct\n"
    "    intentional tips on the same content are not collapsed.\n\n"
    "    Mirrors the stable ``msgtip:{mid}`` / ``bctip:{msg_id}`` pattern.\n"
    "    \"\"\"\n"
    "    crid = (client_request_id or \"\").strip()\n"
    "    if crid:\n"
    "        return f\"{surface}:{content_id}:{crid}\"\n"
    "    return f\"{surface}:{content_id}:{uuid.uuid4().hex}\"\n"
)
sub_once(NF, helper, helper_new, "A3: add _stable_tip_idem helper")

# Add client_request_id to the four newsfeed tip request models.
CRID_FIELD = (
    "    # TIPX-A3: client-supplied idempotency key. The same id for the same tip\n"
    "    # action replays the receipt (a double-tap / retry charges once).\n"
    "    client_request_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r\"[A-Za-z0-9._:-]+\")\n"
)
sub_once(NF,
    "class TipRequest(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    # TIP-301: name an explicit / tip-default payment method for the comment\n"
    "    # tip so charge_tip can resolve the tipper's saved PM (falls back to\n"
    "    # tip-default -> default when None).\n"
    "    payment_method_id: Optional[str] = None\n",
    "class TipRequest(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    # TIP-301: name an explicit / tip-default payment method for the comment\n"
    "    # tip so charge_tip can resolve the tipper's saved PM (falls back to\n"
    "    # tip-default -> default when None).\n"
    "    payment_method_id: Optional[str] = None\n"
    + CRID_FIELD,
    "A3: client_request_id on TipRequest")

sub_once(NF,
    "class PostTipRequest(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    payment_method_id: Optional[str] = None\n",
    "class PostTipRequest(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    payment_method_id: Optional[str] = None\n"
    + CRID_FIELD,
    "A3: client_request_id on PostTipRequest")

sub_once(NF,
    "class PostTipReactRequest(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    emoji: Optional[str] = None\n"
    "    payment_method_id: Optional[str] = None\n",
    "class PostTipReactRequest(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    emoji: Optional[str] = None\n"
    "    payment_method_id: Optional[str] = None\n"
    + CRID_FIELD,
    "A3: client_request_id on PostTipReactRequest")

# CommentIn carries tip_amount_cents (comment-carry) -> add client_request_id there.
sub_once(NF,
    "    tip_amount_cents: Optional[int] = Field(default=None, ge=1)\n",
    "    tip_amount_cents: Optional[int] = Field(default=None, ge=1)\n"
    "    tip_client_request_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r\"[A-Za-z0-9._:-]+\")  # TIPX-A3\n",
    "A3: tip_client_request_id on comment-carry model")

# Replace the four fresh keys in newsfeed with stable-key calls.
sub_once(NF,
    "            content_id=post_id,\n"
    "            meta={\"post_id\": post_id},\n"
    "            idempotency_key=new_id(\"posttip\"),\n",
    "            content_id=post_id,\n"
    "            meta={\"post_id\": post_id},\n"
    "            idempotency_key=_stable_tip_idem(\"posttip\", user_id, post_id, getattr(req, \"client_request_id\", None)),\n",
    "A3: stable posttip key")

sub_once(NF,
    "        content_id=post_id,\n"
    "        meta={\"post_id\": post_id, \"emoji\": emoji},\n"
    "        idempotency_key=new_id(\"postreacttip\"),\n",
    "        content_id=post_id,\n"
    "        meta={\"post_id\": post_id, \"emoji\": emoji},\n"
    "        idempotency_key=_stable_tip_idem(\"postreacttip\", user_id, post_id, getattr(req, \"client_request_id\", None)),\n",
    "A3: stable postreacttip key")

sub_once(NF,
    "            meta={\"post_id\": post_id, \"comment_id\": comment_id, \"carried\": True},\n"
    "            idempotency_key=new_id(\"cmtcarry\"),\n",
    "            meta={\"post_id\": post_id, \"comment_id\": comment_id, \"carried\": True},\n"
    "            idempotency_key=_stable_tip_idem(\"cmtcarry\", user_id, comment_id, getattr(req, \"tip_client_request_id\", None)),\n",
    "A3: stable cmtcarry key")

sub_once(NF,
    "            meta={\"post_id\": post_id, \"comment_id\": comment_id},\n"
    "            idempotency_key=new_id(\"cmttip\"),\n",
    "            meta={\"post_id\": post_id, \"comment_id\": comment_id},\n"
    "            idempotency_key=_stable_tip_idem(\"cmttip\", tipper_id, comment_id, getattr(req, \"client_request_id\", None)),\n",
    "A3: stable cmttip key")

# ---------------------------------------------------------------------------
# A3 messaging: msgreacttip + post-hoc msgtip.
# ---------------------------------------------------------------------------
MSG = "app/routers/messaging.py"

# TipReactIn + SendTipIn: add client_request_id.
sub_once(MSG,
    "class TipReactIn(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    emoji: Optional[str] = Field(default=None, max_length=64)\n"
    "    payment_method_id: Optional[str] = Field(default=None, max_length=200)\n",
    "class TipReactIn(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    emoji: Optional[str] = Field(default=None, max_length=64)\n"
    "    payment_method_id: Optional[str] = Field(default=None, max_length=200)\n"
    "    client_request_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r\"[A-Za-z0-9._:-]+\")  # TIPX-A3\n",
    "A3: client_request_id on TipReactIn")

sub_once(MSG,
    "class SendTipIn(BaseModel):\n"
    "    amount_cents: int = Field(ge=1, le=100_000)\n"
    "    currency: str = \"USD\"\n"
    "    note: Optional[str] = Field(default=None, max_length=500)\n"
    "    payment_method_id: Optional[str] = None\n",
    "class SendTipIn(BaseModel):\n"
    "    amount_cents: int = Field(ge=1, le=100_000)\n"
    "    currency: str = \"USD\"\n"
    "    note: Optional[str] = Field(default=None, max_length=500)\n"
    "    payment_method_id: Optional[str] = None\n"
    "    client_request_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r\"[A-Za-z0-9._:-]+\")  # TIPX-A3\n",
    "A3: client_request_id on SendTipIn")

# msgreacttip key: stable when a client id is supplied.
sub_once(MSG,
    "        idempotency_key=f\"msgreacttip:{message_id}:{uuid.uuid4().hex}\",",
    "        idempotency_key=(f\"msgreacttip:{message_id}:{inp.client_request_id}\" if getattr(inp, \"client_request_id\", None) else f\"msgreacttip:{message_id}:{uuid.uuid4().hex}\"),  # TIPX-A3",
    "A3: stable msgreacttip key")

# post-hoc msgtip: stable "msgtip:{message_id}" (a message carries at most one
# tip attribute, so per-message is stable and safe -- mirrors the inline send).
sub_once(MSG,
    "            meta={\"conversation_id\": conversation_id},\n"
    "            idempotency_key=\"msgtip:\" + new_id(),\n"
    "            tip_payment_id=tip_payment_id,\n",
    "            meta={\"conversation_id\": conversation_id},\n"
    "            idempotency_key=(f\"msgtip:{message_id}:{inp.client_request_id}\" if getattr(inp, \"client_request_id\", None) else f\"msgtip:{message_id}\"),  # TIPX-A3\n"
    "            tip_payment_id=tip_payment_id,\n",
    "A3: stable post-hoc msgtip key")

# ---------------------------------------------------------------------------
# A3 video: videotip + vidcmttip.
# ---------------------------------------------------------------------------
VID = "app/routers/video_listing.py"
sub_once(VID,
    "class VideoTipIn(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    payment_method_id: Optional[str] = None\n\n\n"
    "class VideoTipOut(BaseModel):\n",
    "class VideoTipIn(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    payment_method_id: Optional[str] = None\n"
    "    client_request_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r\"[A-Za-z0-9._:-]+\")  # TIPX-A3\n\n\n"
    "class VideoTipOut(BaseModel):\n",
    "A3: client_request_id on VideoTipIn")
sub_once(VID,
    "class VideoCommentTipIn(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    payment_method_id: Optional[str] = None\n",
    "class VideoCommentTipIn(BaseModel):\n"
    "    amount_cents: int = Field(..., ge=1)\n"
    "    currency: str = \"usd\"\n"
    "    payment_method_id: Optional[str] = None\n"
    "    client_request_id: Optional[str] = Field(default=None, min_length=1, max_length=128, pattern=r\"[A-Za-z0-9._:-]+\")  # TIPX-A3\n",
    "A3: client_request_id on VideoCommentTipIn")

sub_once(VID,
    "        content_id=video_id,\n"
    "        meta={\"video_id\": video_id},\n"
    "        idempotency_key=\"videotip:\" + uuid.uuid4().hex,\n",
    "        content_id=video_id,\n"
    "        meta={\"video_id\": video_id},\n"
    "        idempotency_key=(f\"videotip:{video_id}:{body.client_request_id}\" if getattr(body, \"client_request_id\", None) else \"videotip:\" + uuid.uuid4().hex),  # TIPX-A3\n",
    "A3: stable videotip key")

sub_once(VID,
    "        meta={\"video_id\": video_id, \"comment_id\": comment_id},\n"
    "        idempotency_key=\"vidcmttip:\" + uuid.uuid4().hex,\n",
    "        meta={\"video_id\": video_id, \"comment_id\": comment_id},\n"
    "        idempotency_key=(f\"vidcmttip:{comment_id}:{body.client_request_id}\" if getattr(body, \"client_request_id\", None) else \"vidcmttip:\" + uuid.uuid4().hex),  # TIPX-A3\n",
    "A3: stable vidcmttip key")

# Need VideoTipIn to carry client_request_id too.
print("changed:", len(changed))
