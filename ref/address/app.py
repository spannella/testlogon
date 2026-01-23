"""
app.py — Address Management + Autocomplete + UPS Shipping (Estimate + Label) with 2 billing workflows
===============================================================================================

Supports:
  Address management
    - Add US postal address
    - Verify US postal address (Smarty US Street and/or UPS Address Validation)
    - List US postal addresses
    - Search saved addresses
    - Autocomplete/search (Smarty Autocomplete Pro + UPS candidate suggestions)
    - Remove postal address
    - Set/Get location pin
    - Set primary mailing address
    - Set billing address for a payment method
    - Mail verification: request/respond/tracking (stored state machine)

  UPS Shipping
    - Shipping estimate (UPS Rating API) from stored addresses
    - Prepaid shipping label (UPS Shipping API) with billing workflows:
        1) PLATFORM_PREPAID: bill your UPS account; you charge user
        2) BILL_RECEIVER or BILL_THIRD_PARTY: bill the user’s UPS account

Environment:
  AWS_REGION=us-east-1
  DDB_TABLE=YourSingleTableName

  # Smarty
  SMARTY_AUTH_ID=...
  SMARTY_AUTH_TOKEN=...
  SMARTY_LICENSE=...          # for Autocomplete Pro

  # UPS
  UPS_BASE_URL=https://wwwcie.ups.com
  UPS_CLIENT_ID=...
  UPS_CLIENT_SECRET=...
  UPS_SHIPPER_NUMBER=...      # your platform UPS account number (needed for PLATFORM_PREPAID)
  DEFAULT_SHIP_FROM_ADDRESS_ID=...   # optional (address_id stored in your DB)

Run:
  uvicorn app:app --reload --port 8000
"""

import os
import re
import time
import uuid
import json
import hashlib
from typing import Any, Dict, List, Optional, Literal

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, constr


# =========================================================
# Config
# =========================================================

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
DDB_TABLE = os.environ.get("DDB_TABLE", "")
if not DDB_TABLE:
    raise RuntimeError("Missing env var DDB_TABLE")

# Smarty
SMARTY_AUTH_ID = os.environ.get("SMARTY_AUTH_ID", "")
SMARTY_AUTH_TOKEN = os.environ.get("SMARTY_AUTH_TOKEN", "")
SMARTY_LICENSE = os.environ.get("SMARTY_LICENSE", "")  # for Autocomplete Pro

# UPS
UPS_BASE_URL = os.environ.get("UPS_BASE_URL", "https://wwwcie.ups.com").rstrip("/")
UPS_CLIENT_ID = os.environ.get("UPS_CLIENT_ID", "")
UPS_CLIENT_SECRET = os.environ.get("UPS_CLIENT_SECRET", "")
UPS_SHIPPER_NUMBER = os.environ.get("UPS_SHIPPER_NUMBER", "")
DEFAULT_SHIP_FROM_ADDRESS_ID = os.environ.get("DEFAULT_SHIP_FROM_ADDRESS_ID", "")

# Versions (keep configurable; UPS versions can vary by account/collection)
UPS_ADDRESS_VALIDATION_VERSION = os.environ.get("UPS_ADDRESS_VALIDATION_VERSION", "v2")
UPS_RATING_VERSION = os.environ.get("UPS_RATING_VERSION", "v2")
UPS_SHIPPING_VERSION = os.environ.get("UPS_SHIPPING_VERSION", "v2403")

ddb = boto3.resource("dynamodb", region_name=AWS_REGION)
tbl = ddb.Table(DDB_TABLE)

app = FastAPI(title="Address + UPS Shipping Service (DynamoDB)", version="1.0.0")


# =========================================================
# Auth (simple Bearer token -> user_id)
# =========================================================

def get_user_id(authorization: Optional[str] = Header(default=None)) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    m = re.match(r"^\s*Bearer\s+(.+?)\s*$", authorization, re.IGNORECASE)
    if not m:
        raise HTTPException(status_code=401, detail="Invalid Authorization header (expected Bearer token)")
    user_id = m.group(1).strip()
    if not user_id:
        raise HTTPException(status_code=401, detail="Empty bearer token")
    return user_id


# =========================================================
# Models
# =========================================================

USState = constr(min_length=2, max_length=2)
BillingMode = Literal["PLATFORM_PREPAID", "BILL_RECEIVER", "BILL_THIRD_PARTY"]

class USPostalAddressIn(BaseModel):
    name: Optional[str] = None
    line1: constr(min_length=1, max_length=120)
    line2: Optional[constr(min_length=1, max_length=120)] = None
    city: constr(min_length=1, max_length=80)
    state: USState
    zip5: constr(min_length=5, max_length=5)
    zip4: Optional[constr(min_length=4, max_length=4)] = None
    country: Literal["US", "PR"] = "US"
    label: Optional[str] = None
    notes: Optional[str] = None

class LocationPin(BaseModel):
    lat: float
    lon: float
    source: Optional[str] = None

class USPostalAddressOut(BaseModel):
    address_id: str
    name: Optional[str]
    line1: str
    line2: Optional[str]
    city: str
    state: str
    zip5: str
    zip4: Optional[str]
    country: str
    label: Optional[str]
    notes: Optional[str]
    is_primary_mailing: bool = False
    created_at_ms: int
    updated_at_ms: int
    location_pin: Optional[LocationPin] = None
    last_verify: Optional[Dict[str, Any]] = None
    mail_verified: Optional[bool] = None
    mail_verified_at_ms: Optional[int] = None

class VerifyRequest(BaseModel):
    provider: Literal["smarty", "ups", "both"] = "smarty"
    include_candidates: bool = True
    max_candidates: int = Field(default=10, ge=0, le=50)

class VerifyResult(BaseModel):
    provider: str
    valid: bool
    deliverable: Optional[bool] = None
    messages: List[str] = Field(default_factory=list)
    normalized: Optional[Dict[str, Any]] = None
    candidates: List[Dict[str, Any]] = Field(default_factory=list)

class VerifyResponse(BaseModel):
    address_id: str
    requested_provider: str
    results: List[VerifyResult]

class AutocompleteRequest(BaseModel):
    search: constr(min_length=1, max_length=200)
    max_results: int = Field(default=10, ge=1, le=50)
    include_only_states: Optional[List[str]] = None
    include_only_cities: Optional[List[str]] = None
    prefer_geolocation: Optional[Literal["none", "city", "state"]] = "none"

class AutocompleteCandidate(BaseModel):
    provider: str
    text: str
    raw: Dict[str, Any]

class AutocompleteResponse(BaseModel):
    requested_provider: str
    candidates: List[AutocompleteCandidate]

class AddressSearchResponse(BaseModel):
    query: str
    matches: List[USPostalAddressOut]

class SetPrimaryMailingIn(BaseModel):
    address_id: str

class SetBillingAddressForPaymentMethodIn(BaseModel):
    payment_method_id: constr(min_length=1, max_length=128)
    address_id: constr(min_length=1, max_length=64)

class GetBillingAddressForPaymentMethodOut(BaseModel):
    payment_method_id: str
    billing_address_id: str
    updated_at_ms: int

class UpsBillingProfile(BaseModel):
    account_number: constr(min_length=3, max_length=32)
    default_mode: BillingMode = "BILL_RECEIVER"
    third_party_postal_code: Optional[str] = None
    third_party_country: Optional[str] = "US"

class UpsBillingProfileOut(BaseModel):
    configured: bool
    default_mode: Optional[BillingMode] = None
    masked_account: Optional[str] = None

class PackageSpec(BaseModel):
    weight_lbs: float = Field(..., gt=0)
    length_in: Optional[float] = Field(default=None, gt=0)
    width_in: Optional[float] = Field(default=None, gt=0)
    height_in: Optional[float] = Field(default=None, gt=0)

class UpsEstimateRequest(BaseModel):
    ship_from_address_id: Optional[str] = None
    ship_to_address_id: str
    packages: List[PackageSpec] = Field(..., min_length=1)
    request_option: Literal["Shop", "Rate"] = "Shop"
    service_code: Optional[str] = None
    pickup_type_code: Optional[str] = None
    customer_context: Optional[str] = None

class UpsEstimateResponse(BaseModel):
    raw: Dict[str, Any]

class UpsPrepaidShipRequest(BaseModel):
    ship_from_address_id: Optional[str] = None
    ship_to_address_id: str
    packages: List[PackageSpec] = Field(..., min_length=1)
    service_code: str

    billing_mode: BillingMode = "PLATFORM_PREPAID"
    payer_account_number: Optional[str] = None
    payer_postal_code: Optional[str] = None
    payer_country: Optional[str] = None

    shipper_reference: Optional[str] = None
    customer_context: Optional[str] = None
    label_image_format: Literal["GIF", "PNG", "ZPL", "EPL"] = "GIF"
    label_stock_size: Optional[str] = None

class UpsPrepaidShipResponse(BaseModel):
    tracking_number: Optional[str] = None
    shipment_identification_number: Optional[str] = None
    label_image_base64: Optional[str] = None
    raw: Dict[str, Any]

class UpsVoidRequest(BaseModel):
    shipment_identification_number: str
    tracking_number: Optional[str] = None

class UpsVoidResponse(BaseModel):
    raw: Dict[str, Any]

class MailVerificationRequest(BaseModel):
    address_id: constr(min_length=1, max_length=64)
    carrier: Literal["UPS"] = "UPS"
    initial_tracking_number: Optional[str] = None

class MailVerificationRespond(BaseModel):
    verification_id: constr(min_length=1, max_length=64)
    code: constr(min_length=4, max_length=16)

class MailVerificationTracking(BaseModel):
    verification_id: str
    address_id: str
    status: str
    carrier: str
    tracking_number: Optional[str] = None
    created_at_ms: int
    updated_at_ms: int
    last_event: Optional[str] = None


# =========================================================
# DynamoDB single-table helpers
# =========================================================
# PK: USER#{user_id}
# SK:
#   ADDR#{address_id}
#   META#USER
#   META#UPS_BILLING
#   PMBILL#{payment_method_id}
#   MV#{verification_id}

def now_ms() -> int:
    return int(time.time() * 1000)

def pk_user(user_id: str) -> str:
    return f"USER#{user_id}"

def sk_addr(address_id: str) -> str:
    return f"ADDR#{address_id}"

def sk_meta_user() -> str:
    return "META#USER"

def sk_ups_billing_profile() -> str:
    return "META#UPS_BILLING"

def sk_pm_billing(payment_method_id: str) -> str:
    return f"PMBILL#{payment_method_id}"

def sk_mv(verification_id: str) -> str:
    return f"MV#{verification_id}"

def ddb_put_item(item: Dict[str, Any]) -> None:
    try:
        tbl.put_item(Item=item)
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB put_item failed: {msg}")

def ddb_get_item(pk: str, sk: str) -> Optional[Dict[str, Any]]:
    try:
        resp = tbl.get_item(Key={"pk": pk, "sk": sk})
        return resp.get("Item")
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB get_item failed: {msg}")

def ddb_delete_item(pk: str, sk: str) -> None:
    try:
        tbl.delete_item(Key={"pk": pk, "sk": sk})
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB delete_item failed: {msg}")

def ddb_query_begins_with(pk: str, sk_prefix: str, limit: int = 200) -> List[Dict[str, Any]]:
    try:
        resp = tbl.query(
            KeyConditionExpression=Key("pk").eq(pk) & Key("sk").begins_with(sk_prefix),
            Limit=limit,
        )
        return resp.get("Items", [])
    except ClientError as e:
        msg = e.response.get("Error", {}).get("Message", str(e))
        raise HTTPException(status_code=500, detail=f"DynamoDB query failed: {msg}")


# =========================================================
# Mapping helpers
# =========================================================

def item_to_address_out(item: Dict[str, Any]) -> USPostalAddressOut:
    pin = item.get("location_pin")
    pin_obj = LocationPin(**pin) if isinstance(pin, dict) else None
    return USPostalAddressOut(
        address_id=item["address_id"],
        name=item.get("name"),
        line1=item["line1"],
        line2=item.get("line2"),
        city=item["city"],
        state=item["state"],
        zip5=item["zip5"],
        zip4=item.get("zip4"),
        country=item.get("country", "US"),
        label=item.get("label"),
        notes=item.get("notes"),
        is_primary_mailing=bool(item.get("is_primary_mailing", False)),
        created_at_ms=int(item.get("created_at_ms", 0)),
        updated_at_ms=int(item.get("updated_at_ms", 0)),
        location_pin=pin_obj,
        last_verify=item.get("last_verify"),
        mail_verified=item.get("mail_verified"),
        mail_verified_at_ms=item.get("mail_verified_at_ms"),
    )

def require_address_owned(user_id: str, address_id: str) -> Dict[str, Any]:
    item = ddb_get_item(pk_user(user_id), sk_addr(address_id))
    if not item:
        raise HTTPException(status_code=404, detail="Address not found")
    if item.get("type") != "address":
        raise HTTPException(status_code=404, detail="Address not found")
    return item

def addr_item_to_in(item: Dict[str, Any]) -> USPostalAddressIn:
    return USPostalAddressIn(
        name=item.get("name"),
        line1=item["line1"],
        line2=item.get("line2"),
        city=item["city"],
        state=item["state"],
        zip5=item["zip5"],
        zip4=item.get("zip4"),
        country=item.get("country", "US"),
        label=item.get("label"),
        notes=item.get("notes"),
    )


# =========================================================
# Smarty clients
# =========================================================

class SmartyStreetClient:
    def __init__(self, auth_id: str, auth_token: str):
        self.auth_id = auth_id
        self.auth_token = auth_token
        self.base = "https://us-street.api.smarty.com"

    def configured(self) -> bool:
        return bool(self.auth_id and self.auth_token)

    async def verify(self, a: USPostalAddressIn, candidates: int = 10) -> List[Dict[str, Any]]:
        if not self.configured():
            raise HTTPException(status_code=500, detail="Smarty US Street not configured")
        url = f"{self.base}/street-address"
        params = {
            "auth-id": self.auth_id,
            "auth-token": self.auth_token,
            "street": a.line1,
            "street2": a.line2 or "",
            "city": a.city,
            "state": a.state,
            "zipcode": a.zip5 + (f"-{a.zip4}" if a.zip4 else ""),
            "candidates": str(max(0, min(50, candidates))),
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Smarty US Street error {r.status_code}: {r.text}")
            data = r.json()
            if not isinstance(data, list):
                raise HTTPException(status_code=502, detail=f"Unexpected Smarty US Street response: {data}")
            return data

class SmartyAutocompleteProClient:
    def __init__(self, auth_id: str, auth_token: str, license_key: str):
        self.auth_id = auth_id
        self.auth_token = auth_token
        self.license_key = license_key
        self.base = "https://us-autocomplete-pro.api.smartystreets.com"

    def configured(self) -> bool:
        return bool(self.auth_id and self.auth_token and self.license_key)

    async def lookup(self, req: AutocompleteRequest) -> Dict[str, Any]:
        if not self.configured():
            raise HTTPException(status_code=500, detail="Smarty Autocomplete Pro not configured")
        url = f"{self.base}/lookup"
        params: Dict[str, Any] = {
            "auth-id": self.auth_id,
            "auth-token": self.auth_token,
            "license": self.license_key,
            "search": req.search,
            "max_results": str(req.max_results),
            "prefer_geolocation": req.prefer_geolocation or "none",
        }
        if req.include_only_states:
            params["include_only_states"] = ",".join(req.include_only_states)
        if req.include_only_cities:
            params["include_only_cities"] = ",".join(req.include_only_cities)

        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, params=params)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Smarty Autocomplete error {r.status_code}: {r.text}")
            return r.json()

smarty_street = SmartyStreetClient(SMARTY_AUTH_ID, SMARTY_AUTH_TOKEN)
smarty_auto = SmartyAutocompleteProClient(SMARTY_AUTH_ID, SMARTY_AUTH_TOKEN, SMARTY_LICENSE)


# =========================================================
# UPS OAuth + APIs
# =========================================================

class UpsTokenCache:
    def __init__(self):
        self.token: Optional[str] = None
        self.expires_at_ms: int = 0

    def valid(self) -> bool:
        return self.token is not None and now_ms() < (self.expires_at_ms - 30_000)

UPS_TOKEN = UpsTokenCache()

class UpsClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret

    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.base_url)

    async def _get_token(self) -> str:
        if not self.configured():
            raise HTTPException(status_code=500, detail="UPS not configured (UPS_CLIENT_ID/UPS_CLIENT_SECRET/UPS_BASE_URL)")

        if UPS_TOKEN.valid():
            return UPS_TOKEN.token  # type: ignore

        url = f"{self.base_url}/security/v1/oauth/token"
        data = {"grant_type": "client_credentials"}
        auth = (self.client_id, self.client_secret)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with httpx.AsyncClient(timeout=12.0) as client:
            r = await client.post(url, data=data, auth=auth, headers=headers)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"UPS token error {r.status_code}: {r.text}")
            payload = r.json()
            token = payload.get("access_token")
            expires_in = int(payload.get("expires_in", 3600))
            if not token:
                raise HTTPException(status_code=502, detail=f"UPS token missing access_token: {payload}")

            UPS_TOKEN.token = token
            UPS_TOKEN.expires_at_ms = now_ms() + expires_in * 1000
            return token

    async def address_validation_candidates(self, a: USPostalAddressIn, maximum_candidate_list_size: int = 10) -> Dict[str, Any]:
        token = await self._get_token()
        url = f"{self.base_url}/api/addressvalidation/{UPS_ADDRESS_VALIDATION_VERSION}/1"
        params = {
            "regionalrequestindicator": "True",
            "maximumcandidatelistsize": str(max(1, min(50, maximum_candidate_list_size))),
        }
        body = {
            "XAVRequest": {
                "AddressKeyFormat": {
                    "ConsigneeName": a.name or "",
                    "AddressLine": [a.line1] + ([a.line2] if a.line2 else []),
                    "PoliticalDivision2": a.city,
                    "PoliticalDivision1": a.state,
                    "PostcodePrimaryLow": a.zip5,
                    **({"PostcodeExtendedLow": a.zip4} if a.zip4 else {}),
                    "CountryCode": a.country,
                }
            }
        }
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=14.0) as client:
            r = await client.post(url, params=params, headers=headers, json=body)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"UPS address validation error {r.status_code}: {r.text}")
            return r.json()

    async def rating(self, request_option: Literal["Rate", "Shop"], body: Dict[str, Any]) -> Dict[str, Any]:
        token = await self._get_token()
        url = f"{self.base_url}/api/rating/{UPS_RATING_VERSION}/{request_option}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(url, headers=headers, json=body)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"UPS rating error {r.status_code}: {r.text}")
            return r.json()

    async def ship(self, body: Dict[str, Any]) -> Dict[str, Any]:
        token = await self._get_token()
        url = f"{self.base_url}/api/shipments/{UPS_SHIPPING_VERSION}/ship"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "transId": str(uuid.uuid4()),
            "transactionSrc": "address-service",
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(url, headers=headers, json=body)
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"UPS ship error {r.status_code}: {r.text}")
            return r.json()

    async def void_shipment(self, body: Dict[str, Any]) -> Dict[str, Any]:
        token = await self._get_token()
        url = f"{self.base_url}/api/shipments/{UPS_SHIPPING_VERSION}/void"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "transId": str(uuid.uuid4()),
            "transactionSrc": "address-service",
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.delete(url, headers=headers, json=body)
            if r.status_code not in (200, 202):
                raise HTTPException(status_code=502, detail=f"UPS void error {r.status_code}: {r.text}")
            return r.json()

ups = UpsClient(UPS_BASE_URL, UPS_CLIENT_ID, UPS_CLIENT_SECRET)


# =========================================================
# Provider response interpreters
# =========================================================

def interpret_smarty_street(cands: List[Dict[str, Any]], include_candidates: bool) -> VerifyResult:
    if not cands:
        return VerifyResult(provider="smarty", valid=False, messages=["No match from Smarty"], candidates=[])

    top = cands[0]
    analysis = top.get("analysis") or {}
    dpv_match_code = analysis.get("dpv_match_code")
    deliverable = (dpv_match_code == "Y") if dpv_match_code is not None else None

    normalized = {
        "delivery_line_1": top.get("delivery_line_1"),
        "last_line": top.get("last_line"),
        "components": top.get("components"),
        "metadata": top.get("metadata"),
        "analysis": analysis,
    }

    return VerifyResult(
        provider="smarty",
        valid=True,
        deliverable=deliverable,
        normalized=normalized,
        candidates=(cands if include_candidates else []),
    )

def interpret_ups_xav(resp: Dict[str, Any], include_candidates: bool) -> VerifyResult:
    xav = resp.get("XAVResponse") or resp
    response = xav.get("Response", {})
    status = response.get("ResponseStatus") or {}
    code = str(status.get("Code", ""))
    ok = (code == "1")

    cand = xav.get("Candidate")
    candidates: List[Dict[str, Any]] = []
    if isinstance(cand, list):
        candidates = cand
    elif isinstance(cand, dict):
        candidates = [cand]

    normalized = {"Candidate0": candidates[0]} if candidates else None
    msgs: List[str] = []
    if not ok:
        msgs.append(f"UPS ResponseStatus not success: {status}")

    return VerifyResult(
        provider="ups",
        valid=ok and (len(candidates) > 0),
        normalized=normalized,
        messages=msgs,
        candidates=(candidates if include_candidates else []),
    )


# =========================================================
# Address CRUD + Search
# =========================================================

@app.post("/addresses/us", response_model=USPostalAddressOut)
def add_us_postal_address(body: USPostalAddressIn, user_id: str = Depends(get_user_id)):
    address_id = uuid.uuid4().hex
    ts = now_ms()
    item = {
        "pk": pk_user(user_id),
        "sk": sk_addr(address_id),
        "type": "address",
        "address_id": address_id,
        "name": body.name,
        "line1": body.line1,
        "line2": body.line2,
        "city": body.city,
        "state": body.state.upper(),
        "zip5": body.zip5,
        "zip4": body.zip4,
        "country": body.country,
        "label": body.label,
        "notes": body.notes,
        "created_at_ms": ts,
        "updated_at_ms": ts,
        "location_pin": None,
        "is_primary_mailing": False,
        "last_verify": None,
        "mail_verified": False,
        "mail_verified_at_ms": None,
    }
    ddb_put_item(item)
    return item_to_address_out(item)

@app.get("/addresses/us", response_model=List[USPostalAddressOut])
def list_us_postal_addresses(
    user_id: str = Depends(get_user_id),
    limit: int = Query(default=200, ge=1, le=500),
):
    items = ddb_query_begins_with(pk_user(user_id), "ADDR#", limit=limit)
    items = [it for it in items if it.get("type") == "address"]
    items.sort(key=lambda x: x.get("created_at_ms", 0), reverse=True)
    return [item_to_address_out(it) for it in items]

@app.delete("/addresses/us/{address_id}")
def remove_postal_address(address_id: str, user_id: str = Depends(get_user_id)):
    # Clear primary if needed
    meta = ddb_get_item(pk_user(user_id), sk_meta_user())
    if meta and meta.get("primary_mailing_address_id") == address_id:
        meta["primary_mailing_address_id"] = None
        meta["updated_at_ms"] = now_ms()
        ddb_put_item(meta)

    ddb_delete_item(pk_user(user_id), sk_addr(address_id))
    return {"ok": True}

@app.get("/addresses/search", response_model=AddressSearchResponse)
def search_saved_addresses(
    q: str = Query(..., min_length=1, max_length=120),
    user_id: str = Depends(get_user_id),
):
    items = ddb_query_begins_with(pk_user(user_id), "ADDR#", limit=500)
    qn = q.strip().lower()

    def hay(it: Dict[str, Any]) -> str:
        parts = [
            it.get("name", ""),
            it.get("label", ""),
            it.get("line1", ""),
            it.get("line2", ""),
            it.get("city", ""),
            it.get("state", ""),
            it.get("zip5", ""),
            it.get("zip4", ""),
            it.get("country", ""),
        ]
        return " ".join([p for p in parts if p]).lower()

    matches = [
        it for it in items
        if it.get("type") == "address" and qn in hay(it)
    ]
    matches.sort(key=lambda x: x.get("updated_at_ms", 0), reverse=True)
    return AddressSearchResponse(query=q, matches=[item_to_address_out(m) for m in matches])


# =========================================================
# Location Pin
# =========================================================

@app.put("/addresses/us/{address_id}/pin", response_model=USPostalAddressOut)
def set_location_pin(address_id: str, pin: LocationPin, user_id: str = Depends(get_user_id)):
    it = require_address_owned(user_id, address_id)
    it["location_pin"] = pin.model_dump()
    it["updated_at_ms"] = now_ms()
    ddb_put_item(it)
    return item_to_address_out(it)

@app.get("/addresses/us/{address_id}/pin", response_model=LocationPin)
def get_location_pin(address_id: str, user_id: str = Depends(get_user_id)):
    it = require_address_owned(user_id, address_id)
    pin = it.get("location_pin")
    if not pin:
        raise HTTPException(status_code=404, detail="No location pin set")
    return LocationPin(**pin)


# =========================================================
# Primary mailing address
# =========================================================

@app.put("/addresses/us/primary-mailing")
def set_primary_mailing(body: SetPrimaryMailingIn, user_id: str = Depends(get_user_id)):
    _ = require_address_owned(user_id, body.address_id)
    ts = now_ms()

    meta = ddb_get_item(pk_user(user_id), sk_meta_user())
    if not meta:
        meta = {
            "pk": pk_user(user_id),
            "sk": sk_meta_user(),
            "type": "user_meta",
            "created_at_ms": ts,
        }
    meta["primary_mailing_address_id"] = body.address_id
    meta["updated_at_ms"] = ts
    ddb_put_item(meta)

    # Update flags across addresses (small-N user space)
    addrs = ddb_query_begins_with(pk_user(user_id), "ADDR#", limit=500)
    for it in addrs:
        if it.get("type") != "address":
            continue
        desired = (it.get("address_id") == body.address_id)
        if bool(it.get("is_primary_mailing", False)) != desired:
            it["is_primary_mailing"] = desired
            it["updated_at_ms"] = ts
            ddb_put_item(it)

    return {"ok": True, "primary_mailing_address_id": body.address_id}


# =========================================================
# Billing address for payment method (simple mapping)
# =========================================================

@app.put("/payment_methods/billing-address")
def set_billing_address_for_payment_method(body: SetBillingAddressForPaymentMethodIn, user_id: str = Depends(get_user_id)):
    _ = require_address_owned(user_id, body.address_id)
    ts = now_ms()
    item = {
        "pk": pk_user(user_id),
        "sk": sk_pm_billing(body.payment_method_id),
        "type": "payment_method_billing",
        "payment_method_id": body.payment_method_id,
        "billing_address_id": body.address_id,
        "created_at_ms": ts,
        "updated_at_ms": ts,
    }
    ddb_put_item(item)
    return {"ok": True, "payment_method_id": body.payment_method_id, "billing_address_id": body.address_id}

@app.get("/payment_methods/{payment_method_id}/billing-address", response_model=GetBillingAddressForPaymentMethodOut)
def get_billing_address_for_payment_method(payment_method_id: str, user_id: str = Depends(get_user_id)):
    it = ddb_get_item(pk_user(user_id), sk_pm_billing(payment_method_id))
    if not it or it.get("type") != "payment_method_billing":
        raise HTTPException(status_code=404, detail="No billing address set for this payment method")
    return GetBillingAddressForPaymentMethodOut(
        payment_method_id=payment_method_id,
        billing_address_id=it["billing_address_id"],
        updated_at_ms=int(it.get("updated_at_ms", 0)),
    )


# =========================================================
# Verify stored address (Smarty and/or UPS)
# =========================================================

@app.post("/addresses/us/{address_id}/verify", response_model=VerifyResponse)
async def verify_address(address_id: str, req: VerifyRequest, user_id: str = Depends(get_user_id)):
    item = require_address_owned(user_id, address_id)
    a = addr_item_to_in(item)

    results: List[VerifyResult] = []

    if req.provider in ("smarty", "both"):
        cands = await smarty_street.verify(a, candidates=req.max_candidates if req.include_candidates else 1)
        results.append(interpret_smarty_street(cands, req.include_candidates))

    if req.provider in ("ups", "both"):
        raw = await ups.address_validation_candidates(a, maximum_candidate_list_size=req.max_candidates)
        results.append(interpret_ups_xav(raw, req.include_candidates))

    snap = {
        "ts_ms": now_ms(),
        "requested_provider": req.provider,
        "results": [r.model_dump() for r in results],
    }
    item["last_verify"] = snap
    item["updated_at_ms"] = now_ms()
    ddb_put_item(item)

    return VerifyResponse(address_id=address_id, requested_provider=req.provider, results=results)


# =========================================================
# Autocomplete from providers (Smarty + UPS) and merged
# =========================================================

@app.post("/providers/smarty/autocomplete", response_model=AutocompleteResponse)
async def smarty_autocomplete(req: AutocompleteRequest, user_id: str = Depends(get_user_id)):
    raw = await smarty_auto.lookup(req)

    suggestions = raw.get("suggestions") or raw.get("Suggestions") or []
    candidates: List[AutocompleteCandidate] = []
    if isinstance(suggestions, list):
        for s in suggestions[: req.max_results]:
            txt = s.get("text") or s.get("Text") or json.dumps(s)
            candidates.append(AutocompleteCandidate(provider="smarty", text=str(txt), raw=s))

    return AutocompleteResponse(requested_provider="smarty", candidates=candidates)

@app.post("/providers/ups/autocomplete", response_model=AutocompleteResponse)
async def ups_autocomplete(req: AutocompleteRequest, user_id: str = Depends(get_user_id)):
    """
    UPS "autocomplete" here is implemented as Address Validation candidate suggestions.
    We do a best-effort parse of `search` into line1/city/state/zip if possible.
    """
    s = req.search.strip()

    # Rough parser: "123 main st, New York, NY 10001" or "123 main st,New York,NY 10001-1234"
    line1 = s
    city = "New York"
    state = "NY"
    zip5 = "10001"
    zip4 = None

    m = re.match(r"^(.*?),(.*?),(.*?)\s+(\d{5})(?:-(\d{4}))?$", s)
    if m:
        line1 = m.group(1).strip()
        city = m.group(2).strip()
        st = m.group(3).strip()
        state = (st[:2].upper() if len(st) >= 2 else "NY")
        zip5 = m.group(4)
        zip4 = m.group(5) if m.group(5) else None

    a = USPostalAddressIn(
        name=None,
        line1=line1,
        line2=None,
        city=city,
        state=state,
        zip5=zip5,
        zip4=zip4,
        country="US",
    )

    raw = await ups.address_validation_candidates(a, maximum_candidate_list_size=req.max_results)
    xav = raw.get("XAVResponse") or raw
    cand = xav.get("Candidate")
    candidates_list: List[Dict[str, Any]] = []
    if isinstance(cand, list):
        candidates_list = cand
    elif isinstance(cand, dict):
        candidates_list = [cand]

    out: List[AutocompleteCandidate] = []
    for c in candidates_list[: req.max_results]:
        akf = (c.get("AddressKeyFormat") or {})
        addr_lines = akf.get("AddressLine")
        if isinstance(addr_lines, list):
            addr_line = " ".join([str(x) for x in addr_lines if x])
        else:
            addr_line = str(addr_lines or "")
        txt = ", ".join(
            [
                addr_line,
                str(akf.get("PoliticalDivision2") or ""),
                str(akf.get("PoliticalDivision1") or ""),
                str(akf.get("PostcodePrimaryLow") or ""),
            ]
        ).strip(" ,")
        out.append(AutocompleteCandidate(provider="ups", text=txt or json.dumps(c), raw=c))

    return AutocompleteResponse(requested_provider="ups", candidates=out)

@app.post("/autocomplete/both", response_model=AutocompleteResponse)
async def autocomplete_both(req: AutocompleteRequest, user_id: str = Depends(get_user_id)):
    all_cands: List[AutocompleteCandidate] = []

    try:
        s = await smarty_autocomplete(req, user_id)
        all_cands.extend(s.candidates)
    except HTTPException:
        pass

    try:
        u = await ups_autocomplete(req, user_id)
        all_cands.extend(u.candidates)
    except HTTPException:
        pass

    seen = set()
    merged: List[AutocompleteCandidate] = []
    for c in all_cands:
        k = c.text.strip().lower()
        if k and k not in seen:
            seen.add(k)
            merged.append(c)

    return AutocompleteResponse(requested_provider="both", candidates=merged[: req.max_results])


# =========================================================
# UPS Billing Profile (user-provided UPS account)
# =========================================================

@app.put("/users/me/ups-billing-profile", response_model=UpsBillingProfileOut)
def set_ups_billing_profile(body: UpsBillingProfile, user_id: str = Depends(get_user_id)):
    ts = now_ms()
    item = {
        "pk": pk_user(user_id),
        "sk": sk_ups_billing_profile(),
        "type": "ups_billing_profile",
        # NOTE: strongly recommended to encrypt this field (KMS/app-layer) in production
        "account_number": body.account_number,
        "default_mode": body.default_mode,
        "third_party_postal_code": body.third_party_postal_code,
        "third_party_country": body.third_party_country,
        "created_at_ms": ts,
        "updated_at_ms": ts,
    }
    ddb_put_item(item)
    masked = body.account_number[-4:].rjust(len(body.account_number), "*")
    return UpsBillingProfileOut(configured=True, default_mode=body.default_mode, masked_account=masked)

@app.get("/users/me/ups-billing-profile", response_model=UpsBillingProfileOut)
def get_ups_billing_profile(user_id: str = Depends(get_user_id)):
    item = ddb_get_item(pk_user(user_id), sk_ups_billing_profile())
    if not item or item.get("type") != "ups_billing_profile":
        return UpsBillingProfileOut(configured=False)
    acc = item.get("account_number", "")
    masked = acc[-4:].rjust(len(acc), "*") if acc else None
    return UpsBillingProfileOut(configured=True, default_mode=item.get("default_mode"), masked_account=masked)

@app.delete("/users/me/ups-billing-profile")
def delete_ups_billing_profile(user_id: str = Depends(get_user_id)):
    ddb_delete_item(pk_user(user_id), sk_ups_billing_profile())
    return {"ok": True}


# =========================================================
# UPS Shipping: estimate + prepaid label with 2 workflows
# =========================================================

def _require_ship_from(user_id: str, ship_from_address_id: Optional[str]) -> Dict[str, Any]:
    if ship_from_address_id:
        return require_address_owned(user_id, ship_from_address_id)
    if DEFAULT_SHIP_FROM_ADDRESS_ID:
        return require_address_owned(user_id, DEFAULT_SHIP_FROM_ADDRESS_ID)
    raise HTTPException(status_code=400, detail="Missing ship_from_address_id and DEFAULT_SHIP_FROM_ADDRESS_ID not set")

def _ups_address_from_item(it: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "AddressLine": [it["line1"]] + ([it.get("line2")] if it.get("line2") else []),
        "City": it["city"],
        "StateProvinceCode": it["state"],
        "PostalCode": it["zip5"] + (f"-{it['zip4']}" if it.get("zip4") else ""),
        "CountryCode": it.get("country", "US"),
    }

def _ups_package_from_spec(p: PackageSpec) -> Dict[str, Any]:
    pkg: Dict[str, Any] = {
        "PackagingType": {"Code": "02"},  # customer supplied package
        "PackageWeight": {"UnitOfMeasurement": {"Code": "LBS"}, "Weight": f"{p.weight_lbs:.2f}"},
    }
    if p.length_in and p.width_in and p.height_in:
        pkg["Dimensions"] = {
            "UnitOfMeasurement": {"Code": "IN"},
            "Length": f"{p.length_in:.2f}",
            "Width": f"{p.width_in:.2f}",
            "Height": f"{p.height_in:.2f}",
        }
    return pkg

def build_payment_information(
    user_id: str,
    mode: BillingMode,
    payer_account_number: Optional[str],
    payer_postal_code: Optional[str],
    payer_country: Optional[str],
) -> Dict[str, Any]:
    """
    PLATFORM_PREPAID: bill your platform UPS account
    BILL_RECEIVER: bill receiver's UPS account (user-provided)
    BILL_THIRD_PARTY: bill a third-party UPS account (user-provided)

    We resolve payer account as:
      - request override payer_account_number, else
      - saved ups-billing-profile.account_number
    """
    if mode == "PLATFORM_PREPAID":
        if not UPS_SHIPPER_NUMBER:
            raise HTTPException(status_code=500, detail="UPS_SHIPPER_NUMBER not configured (required for PLATFORM_PREPAID)")
        return {"ShipmentCharge": [{"Type": "01", "BillShipper": {"AccountNumber": UPS_SHIPPER_NUMBER}}]}

    # Resolve payer account from override or saved profile
    account = payer_account_number
    profile = None
    if not account:
        profile = ddb_get_item(pk_user(user_id), sk_ups_billing_profile())
        if profile and profile.get("type") == "ups_billing_profile":
            account = profile.get("account_number")

    if not account:
        raise HTTPException(status_code=400, detail="Missing payer_account_number and no saved UPS billing profile found")

    if mode == "BILL_RECEIVER":
        return {"ShipmentCharge": [{"Type": "01", "BillReceiver": {"AccountNumber": account}}]}

    # BILL_THIRD_PARTY
    postal = payer_postal_code or (profile.get("third_party_postal_code") if profile else None)
    country = payer_country or (profile.get("third_party_country") if profile else "US")

    bill_third_party: Dict[str, Any] = {"AccountNumber": account}
    # Some configurations want Address for third-party billing; keep optional
    if postal or country:
        bill_third_party["Address"] = {}
        if postal:
            bill_third_party["Address"]["PostalCode"] = postal
        if country:
            bill_third_party["Address"]["CountryCode"] = country

    return {"ShipmentCharge": [{"Type": "01", "BillThirdParty": bill_third_party}]}

@app.post("/shipping/ups/estimate", response_model=UpsEstimateResponse)
async def ups_shipping_estimate(body: UpsEstimateRequest, user_id: str = Depends(get_user_id)):
    ship_from = _require_ship_from(user_id, body.ship_from_address_id)
    ship_to = require_address_owned(user_id, body.ship_to_address_id)

    # For meaningful account rates, your shipper number is typically needed.
    if not UPS_SHIPPER_NUMBER:
        raise HTTPException(status_code=500, detail="UPS_SHIPPER_NUMBER not configured (recommended/required for most rating flows)")

    packages = [_ups_package_from_spec(p) for p in body.packages]

    request_option = body.request_option
    if request_option == "Rate" and not body.service_code:
        raise HTTPException(status_code=400, detail="service_code required when request_option='Rate'")

    rating_body: Dict[str, Any] = {
        "RateRequest": {
            "Request": {
                "RequestOption": request_option,
                "TransactionReference": {"CustomerContext": body.customer_context or "rate-estimate"},
            },
            "Shipment": {
                "Shipper": {
                    "ShipperNumber": UPS_SHIPPER_NUMBER,
                    "Address": _ups_address_from_item(ship_from),
                },
                "ShipTo": {"Address": _ups_address_from_item(ship_to)},
                "ShipFrom": {"Address": _ups_address_from_item(ship_from)},
                "Package": packages,
            },
        }
    }

    if body.service_code:
        rating_body["RateRequest"]["Shipment"]["Service"] = {"Code": body.service_code}
    if body.pickup_type_code:
        rating_body["RateRequest"]["PickupType"] = {"Code": body.pickup_type_code}

    raw = await ups.rating(request_option=request_option, body=rating_body)
    return UpsEstimateResponse(raw=raw)

@app.post("/shipping/ups/label", response_model=UpsPrepaidShipResponse)
async def ups_create_label(body: UpsPrepaidShipRequest, user_id: str = Depends(get_user_id)):
    ship_from = _require_ship_from(user_id, body.ship_from_address_id)
    ship_to = require_address_owned(user_id, body.ship_to_address_id)

    packages = [_ups_package_from_spec(p) for p in body.packages]

    payment_info = build_payment_information(
        user_id=user_id,
        mode=body.billing_mode,
        payer_account_number=body.payer_account_number,
        payer_postal_code=body.payer_postal_code,
        payer_country=body.payer_country,
    )

    ship_body: Dict[str, Any] = {
        "ShipmentRequest": {
            "Request": {
                "RequestOption": "nonvalidate",
                "TransactionReference": {"CustomerContext": body.customer_context or "create-label"},
            },
            "Shipment": {
                "Description": body.shipper_reference or "Shipment",
                "Shipper": {
                    "Name": ship_from.get("name") or "Shipper",
                    # ShipperNumber here is often expected even if billing receiver/third-party
                    # If you want "true customer shipper", you can set this to the payer account for BILL_*.
                    "ShipperNumber": UPS_SHIPPER_NUMBER or "",
                    "Address": _ups_address_from_item(ship_from),
                },
                "ShipTo": {
                    "Name": ship_to.get("name") or "Recipient",
                    "Address": _ups_address_from_item(ship_to),
                },
                "ShipFrom": {
                    "Name": ship_from.get("name") or "Shipper",
                    "Address": _ups_address_from_item(ship_from),
                },
                "Service": {"Code": body.service_code},
                "PaymentInformation": payment_info,
                "Package": packages,
            },
            "LabelSpecification": {
                "LabelImageFormat": {"Code": body.label_image_format},
            },
        }
    }

    if body.label_stock_size:
        ship_body["ShipmentRequest"]["LabelSpecification"]["LabelStockSize"] = body.label_stock_size

    raw = await ups.ship(ship_body)

    shipment_resp = raw.get("ShipmentResponse") or raw
    ship_results = shipment_resp.get("ShipmentResults") or shipment_resp.get("ShipmentResult") or {}

    shipment_id = ship_results.get("ShipmentIdentificationNumber")
    tracking = None
    label_b64 = None

    pkg_results = ship_results.get("PackageResults")
    if isinstance(pkg_results, list) and pkg_results:
        tracking = pkg_results[0].get("TrackingNumber")
        label_b64 = (pkg_results[0].get("ShippingLabel") or {}).get("GraphicImage")
    elif isinstance(pkg_results, dict):
        tracking = pkg_results.get("TrackingNumber")
        label_b64 = (pkg_results.get("ShippingLabel") or {}).get("GraphicImage")

    return UpsPrepaidShipResponse(
        tracking_number=tracking,
        shipment_identification_number=shipment_id,
        label_image_base64=label_b64,
        raw=raw,
    )

@app.post("/shipping/ups/void", response_model=UpsVoidResponse)
async def ups_void(body: UpsVoidRequest, user_id: str = Depends(get_user_id)):
    payload: Dict[str, Any] = {"VoidShipmentRequest": {"ShipmentIdentificationNumber": body.shipment_identification_number}}
    if body.tracking_number:
        payload["VoidShipmentRequest"]["TrackingNumber"] = body.tracking_number
    raw = await ups.void_shipment(payload)
    return UpsVoidResponse(raw=raw)


# =========================================================
# Mail verification (stored state machine)
# =========================================================

def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def _gen_code() -> str:
    return f"{uuid.uuid4().int % 1000000:06d}"

@app.post("/mail_verification/request", response_model=MailVerificationTracking)
def request_mail_verification(req: MailVerificationRequest, user_id: str = Depends(get_user_id)):
    _ = require_address_owned(user_id, req.address_id)

    verification_id = uuid.uuid4().hex
    ts = now_ms()
    code = _gen_code()

    item = {
        "pk": pk_user(user_id),
        "sk": sk_mv(verification_id),
        "type": "mail_verification",
        "verification_id": verification_id,
        "address_id": req.address_id,
        "carrier": req.carrier,
        "status": "REQUESTED",   # REQUESTED -> VERIFIED / FAILED / EXPIRED (you can extend)
        "tracking_number": req.initial_tracking_number,
        "code_hash": _hash_code(code),
        "created_at_ms": ts,
        "updated_at_ms": ts,
        "last_event": "Verification requested",
    }
    ddb_put_item(item)

    # Dev-only: optionally return the code to make local testing easy.
    # DO NOT enable in production.
    debug = os.environ.get("MAIL_VERIFY_DEBUG_RETURN_CODE", "0") == "1"
    out = MailVerificationTracking(
        verification_id=verification_id,
        address_id=req.address_id,
        status=item["status"],
        carrier=req.carrier,
        tracking_number=req.initial_tracking_number,
        created_at_ms=ts,
        updated_at_ms=ts,
        last_event=item["last_event"],
    )
    payload = out.model_dump()
    if debug:
        payload["debug_code"] = code
    return JSONResponse(payload)

@app.post("/mail_verification/respond", response_model=MailVerificationTracking)
def respond_mail_verification(body: MailVerificationRespond, user_id: str = Depends(get_user_id)):
    pk = pk_user(user_id)
    sk = sk_mv(body.verification_id)

    it = ddb_get_item(pk, sk)
    if not it or it.get("type") != "mail_verification":
        raise HTTPException(status_code=404, detail="Verification not found")

    if it.get("status") in ("VERIFIED", "FAILED", "EXPIRED"):
        return MailVerificationTracking(
            verification_id=it["verification_id"],
            address_id=it["address_id"],
            status=it["status"],
            carrier=it["carrier"],
            tracking_number=it.get("tracking_number"),
            created_at_ms=int(it.get("created_at_ms", 0)),
            updated_at_ms=int(it.get("updated_at_ms", 0)),
            last_event=it.get("last_event"),
        )

    ok = (_hash_code(body.code) == it.get("code_hash"))
    ts = now_ms()
    it["status"] = "VERIFIED" if ok else "FAILED"
    it["updated_at_ms"] = ts
    it["last_event"] = "Code verified" if ok else "Invalid code"
    ddb_put_item(it)

    if ok:
        addr = require_address_owned(user_id, it["address_id"])
        addr["mail_verified"] = True
        addr["mail_verified_at_ms"] = ts
        addr["updated_at_ms"] = ts
        ddb_put_item(addr)

    return MailVerificationTracking(
        verification_id=it["verification_id"],
        address_id=it["address_id"],
        status=it["status"],
        carrier=it["carrier"],
        tracking_number=it.get("tracking_number"),
        created_at_ms=int(it.get("created_at_ms", 0)),
        updated_at_ms=ts,
        last_event=it.get("last_event"),
    )

@app.get("/mail_verification/{verification_id}/tracking", response_model=MailVerificationTracking)
def get_mail_verification_tracking(verification_id: str, user_id: str = Depends(get_user_id)):
    it = ddb_get_item(pk_user(user_id), sk_mv(verification_id))
    if not it or it.get("type") != "mail_verification":
        raise HTTPException(status_code=404, detail="Verification not found")
    return MailVerificationTracking(
        verification_id=it["verification_id"],
        address_id=it["address_id"],
        status=it["status"],
        carrier=it["carrier"],
        tracking_number=it.get("tracking_number"),
        created_at_ms=int(it.get("created_at_ms", 0)),
        updated_at_ms=int(it.get("updated_at_ms", 0)),
        last_event=it.get("last_event"),
    )


# =========================================================
# Health
# =========================================================

@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "address-ups-shipping",
        "region": AWS_REGION,
        "table": DDB_TABLE,
        "ups_base_url": UPS_BASE_URL,
        "versions": {
            "address_validation": UPS_ADDRESS_VALIDATION_VERSION,
            "rating": UPS_RATING_VERSION,
            "shipping": UPS_SHIPPING_VERSION,
        },
        "smarty": {
            "street_configured": bool(SMARTY_AUTH_ID and SMARTY_AUTH_TOKEN),
            "autocomplete_configured": bool(SMARTY_AUTH_ID and SMARTY_AUTH_TOKEN and SMARTY_LICENSE),
        },
        "ups_configured": bool(UPS_CLIENT_ID and UPS_CLIENT_SECRET),
        "ups_shipper_configured": bool(UPS_SHIPPER_NUMBER),
    }


# =========================================================
# Error handling
# =========================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"ok": False, "error": exc.detail})

@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"ok": False, "error": "Internal server error", "detail": str(exc)})


"""
DynamoDB table schema:
  - Partition key: pk (string)
  - Sort key: sk (string)

Recommended capacity:
  - On-demand is easiest for dev; provisioned with autoscaling for prod.

This is a single-tenant-per-user keying scheme:
  - All user data lives under pk = USER#{user_id}
"""
