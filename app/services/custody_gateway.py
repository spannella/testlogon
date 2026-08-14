"""Crypto-custody gateway client + in-memory mock (CUSTODY).

This module is the ONLY thing that talks to the external MPC custody gateway.
It signs every ``/v1/*`` call (except health) with an HMAC over
``ts + METHOD + request_target(+query) + body`` using the server-side API secret.

The secret and officer keys are server-to-server credentials and MUST NOT be
exposed to clients or logged.

When the gateway is not configured (no URL/key — the DEV_MODE demo default),
``get_custody_gateway()`` returns a ``_MockCustodyGateway`` with deterministic,
demo-realistic in-memory state so the frontends can render + exercise the full
flow (submit -> screening -> pending_approval -> approve xN -> release -> settled).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from app.core.settings import S

logger = logging.getLogger(__name__)


class CustodyGatewayError(Exception):
    """Raised for gateway-level failures. ``status`` mirrors the HTTP status
    when the gateway answered; ``payload`` is the parsed JSON body (best-effort)."""

    def __init__(self, message: str, status: int = 502, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


# ---------------------------------------------------------------------------
# Supported asset / chain registry. The router builds intent wires from this;
# the mock uses it to shape addresses. Kept intentionally small + explicit.
# `chain_ref` is the value placed in the intent wire's <chain_or_ref> slot.
# ---------------------------------------------------------------------------
ASSET_REGISTRY: List[Dict[str, Any]] = [
    {"asset": "ETH", "chain": "ethereum", "chain_ref": "0x1", "network": "Mainnet", "name": "Ether", "symbol": "ETH", "decimals": 18, "family": "evm"},
    {"asset": "USDC", "chain": "ethereum", "chain_ref": "0x1", "network": "Mainnet", "name": "USD Coin", "symbol": "USDC", "decimals": 6, "family": "evm"},
    {"asset": "USDT", "chain": "ethereum", "chain_ref": "0x1", "network": "Mainnet", "name": "Tether USD", "symbol": "USDT", "decimals": 6, "family": "evm"},
    {"asset": "BNB", "chain": "bsc", "chain_ref": "0x38", "network": "Mainnet", "name": "BNB", "symbol": "BNB", "decimals": 18, "family": "evm"},
    {"asset": "POL", "chain": "polygon", "chain_ref": "0x89", "network": "Mainnet", "name": "Polygon", "symbol": "POL", "decimals": 18, "family": "evm"},
    {"asset": "SOL", "chain": "solana", "chain_ref": "solana-mainnet", "network": "Mainnet", "name": "Solana", "symbol": "SOL", "decimals": 9, "family": "solana"},
    {"asset": "XRP", "chain": "xrpl", "chain_ref": "xrpl-mainnet", "network": "Mainnet", "name": "XRP", "symbol": "XRP", "decimals": 6, "family": "xrp"},
    {"asset": "TRX", "chain": "tron", "chain_ref": "tron-mainnet", "network": "Mainnet", "name": "TRON", "symbol": "TRX", "decimals": 6, "family": "tron"},
    {"asset": "USDT-TRC20", "chain": "tron", "chain_ref": "tron-mainnet", "network": "Mainnet", "name": "Tether USD (TRC-20)", "symbol": "USDT", "decimals": 6, "family": "tron"},
    {"asset": "BTC", "chain": "bitcoin", "chain_ref": "bitcoin-mainnet", "network": "Mainnet", "name": "Bitcoin", "symbol": "BTC", "decimals": 8, "family": "btc"},
    {"asset": "HYPE", "chain": "hyperliquid", "chain_ref": "0x66eee", "network": "Mainnet", "name": "Hyperliquid", "symbol": "HYPE", "decimals": 18, "family": "evm"},
]

_REGISTRY_BY_KEY: Dict[Tuple[str, str], Dict[str, Any]] = {
    (r["asset"].upper(), r["chain"].lower()): r for r in ASSET_REGISTRY
}


def registry_entry(asset: str, chain: str) -> Optional[Dict[str, Any]]:
    return _REGISTRY_BY_KEY.get((str(asset).upper(), str(chain).lower()))


def _now_ms() -> int:
    return int(time.time() * 1000)


# ===========================================================================
# Real client
# ===========================================================================
class CustodyGatewayClient:
    """HMAC-signing HTTP client for the external MPC custody gateway."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        api_secret: str,
        tenant: str,
        verify_tls: bool = False,
        timeout_seconds: float = 15.0,
        officer_keys: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._api_secret = api_secret
        self._tenant = tenant
        self._verify_tls = verify_tls
        self._timeout = timeout_seconds
        self._officer_keys = officer_keys or {}

    # -- signing -----------------------------------------------------------
    def _sign(self, secret: str, ts: str, method: str, request_target: str, body: str) -> str:
        msg = f"{ts}{method}{request_target}{body}".encode("utf-8")
        return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

    def _headers(
        self,
        method: str,
        request_target: str,
        body: str,
        *,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, str]:
        key = api_key or self._api_key
        secret = api_secret or self._api_secret
        ts = str(_now_ms())
        headers = {
            "X-Api-Key": key,
            "X-Api-Timestamp": ts,
            "X-Api-Signature": self._sign(secret, ts, method, request_target, body),
        }
        if body:
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: str = "",
        json_body: Optional[Dict[str, Any]] = None,
        signed: bool = True,
        api_key: Optional[str] = None,
        api_secret: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        import httpx  # lazy: keep import cost off the hot path / dev without httpx

        body = "" if json_body is None else json.dumps(json_body, separators=(",", ":"), sort_keys=True)
        request_target = path if not query else f"{path}?{query}"
        url = f"{self._base_url}{request_target}"
        headers: Dict[str, str] = {}
        if signed:
            headers = self._headers(
                method,
                request_target,
                body,
                api_key=api_key,
                api_secret=api_secret,
                idempotency_key=idempotency_key,
            )
        try:
            with httpx.Client(verify=self._verify_tls, timeout=self._timeout) as client:
                resp = client.request(
                    method,
                    url,
                    headers=headers,
                    content=body.encode("utf-8") if body else None,
                )
        except Exception as exc:  # network / TLS failure — never leak creds
            logger.warning("custody gateway request failed: %s %s: %s", method, path, type(exc).__name__)
            raise CustodyGatewayError(f"gateway unreachable: {type(exc).__name__}", status=502)
        try:
            payload = resp.json() if resp.content else {}
        except Exception:
            payload = {"raw": resp.text[:500]}
        return resp.status_code, payload

    # -- health ------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        _, payload = self._request("GET", "/v1/health", signed=False)
        return payload

    # -- wallets -----------------------------------------------------------
    def create_wallet(self, name: str) -> Dict[str, Any]:
        _, payload = self._request("POST", "/v1/wallets", json_body={"name": name})
        return payload

    def get_address(self, wallet_id: str, user: str, chain: str) -> Dict[str, Any]:
        query = f"user={user}&chain={chain}"
        _, payload = self._request("GET", f"/v1/wallets/{wallet_id}/address", query=query)
        return payload

    # -- withdrawals -------------------------------------------------------
    def create_withdrawal(self, wallet: str, intent: str, idempotency_key: str) -> Tuple[int, Dict[str, Any]]:
        return self._request(
            "POST",
            "/v1/withdrawals",
            json_body={"wallet": wallet, "intent": intent},
            idempotency_key=idempotency_key,
        )

    def approve_withdrawal(self, withdrawal_id: str, approver: str) -> Tuple[int, Dict[str, Any]]:
        officer = self._officer_keys.get(approver) or {}
        return self._request(
            "POST",
            f"/v1/withdrawals/{withdrawal_id}/approvals",
            json_body={"approver": approver},
            api_key=officer.get("key") or self._api_key,
            api_secret=officer.get("secret") or self._api_secret,
        )

    def release_withdrawal(self, withdrawal_id: str) -> Tuple[int, Dict[str, Any]]:
        return self._request("POST", f"/v1/withdrawals/{withdrawal_id}/release", json_body={})

    def get_withdrawal(self, withdrawal_id: str) -> Dict[str, Any]:
        _, payload = self._request("GET", f"/v1/withdrawals/{withdrawal_id}")
        return payload

    # -- vaults ------------------------------------------------------------
    def create_vault(self, name: str) -> Dict[str, Any]:
        _, payload = self._request("POST", "/v1/vaults", json_body={"name": name})
        return payload

    def list_vaults(self) -> Dict[str, Any]:
        _, payload = self._request("GET", "/v1/vaults")
        return payload

    def get_vault(self, vault_id: str) -> Dict[str, Any]:
        _, payload = self._request("GET", f"/v1/vaults/{vault_id}")
        return payload

    def credit_vault(self, vault_id: str, asset: str, amount: float) -> Dict[str, Any]:
        _, payload = self._request(
            "POST", f"/v1/vaults/{vault_id}/credit", json_body={"asset": asset, "amount": amount}
        )
        return payload

    # -- audit -------------------------------------------------------------
    def audit(self) -> Dict[str, Any]:
        _, payload = self._request("GET", "/v1/audit")
        return payload

    def audit_verify(self) -> Dict[str, Any]:
        _, payload = self._request("GET", "/v1/audit/verify")
        return payload

    @staticmethod
    def is_configured() -> bool:
        return bool(S.custody_gateway_url and S.custody_api_key and S.custody_api_secret)


# ===========================================================================
# Mock
# ===========================================================================
def _derive_hex(*parts: str, length: int = 40) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    while len(h) < length:
        h += hashlib.sha256(h.encode("utf-8")).hexdigest()
    return h[:length]


def _mock_address(user: str, family: str, asset: str, chain: str) -> str:
    """Deterministic, chain-appropriate-looking address per (user, asset, chain)."""
    seed = f"{user}|{asset}|{chain}"
    if family == "evm":
        return "0x" + _derive_hex("evm", seed, length=40)
    if family == "solana":
        # base58-ish; use only base58 alphabet chars derived from the hash
        raw = _derive_hex("sol", seed, length=64)
        alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return "".join(alpha[int(raw[i:i + 2], 16) % len(alpha)] for i in range(0, 44 * 2, 2))
    if family == "xrp":
        raw = _derive_hex("xrp", seed, length=50)
        alpha = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
        return "r" + "".join(alpha[int(raw[i:i + 2], 16) % len(alpha)] for i in range(0, 32 * 2, 2))
    if family == "tron":
        raw = _derive_hex("tron", seed, length=50)
        alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return "T" + "".join(alpha[int(raw[i:i + 2], 16) % len(alpha)] for i in range(0, 33 * 2, 2))
    if family == "btc":
        raw = _derive_hex("btc", seed, length=50)
        alpha = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # bech32
        return "bc1q" + "".join(alpha[int(raw[i:i + 2], 16) % len(alpha)] for i in range(0, 38 * 2, 2))
    return "0x" + _derive_hex("gen", seed, length=40)


# Recipients flagged as sanctioned by the mock screening step (demo).
_MOCK_SANCTIONED = {"0x0000000000000000000000000000000000000bad", "sanctioned"}


class _MockCustodyGateway:
    """In-memory deterministic custody gateway for DEV_MODE / no gateway configured.

    State is process-wide (module singleton) so a demo flow persists across
    requests within one server process. Thread-safe via a coarse lock.
    """

    def __init__(self, tenant: str = "testlogon") -> None:
        self._tenant = tenant
        self._lock = threading.RLock()
        self._wallets: Dict[str, Dict[str, Any]] = {}
        self._vaults: Dict[str, Dict[str, Any]] = {}
        self._withdrawals: Dict[str, Dict[str, Any]] = {}
        self._idem: Dict[str, str] = {}  # idempotency-key -> withdrawal_id
        self._audit: List[Dict[str, Any]] = []
        self._audit_prev = "0" * 64
        self._threshold = float(getattr(S, "custody_approval_threshold", 1000))
        self._approvals_required = int(getattr(S, "custody_approvals_required", 2))
        self._seeded_users: set[str] = set()

    # -- audit hash chain --------------------------------------------------
    def _append_audit(self, action: str, detail: Dict[str, Any]) -> None:
        entry_body = {"seq": len(self._audit) + 1, "action": action, "detail": detail, "ts_ms": _now_ms()}
        chained = hashlib.sha256((self._audit_prev + json.dumps(entry_body, sort_keys=True)).encode()).hexdigest()
        entry = {**entry_body, "prev": self._audit_prev, "hash": chained}
        self._audit.append(entry)
        self._audit_prev = chained

    # -- health ------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "status": "ok",
                "daemon": "mock",
                "sign_calls": sum(1 for w in self._withdrawals.values() if w.get("signature")),
                "audit_entries": len(self._audit),
                "compliance": {"screening": "mock", "sanctions_list": "demo"},
            }

    @staticmethod
    def is_configured() -> bool:
        return False

    # -- wallets -----------------------------------------------------------
    def create_wallet(self, name: str) -> Dict[str, Any]:
        with self._lock:
            wallet_id = f"{self._tenant}-{name}"
            if wallet_id not in self._wallets:
                self._wallets[wallet_id] = {
                    "wallet_id": wallet_id,
                    "pubkey": "0x" + _derive_hex("pubkey", wallet_id, length=64),
                }
                self._append_audit("wallet.create", {"wallet_id": wallet_id})
            return dict(self._wallets[wallet_id])

    def get_address(self, wallet_id: str, user: str, chain: str) -> Dict[str, Any]:
        # `chain` here is the chain_ref passed by the router; map back to a family.
        family = "evm"
        for r in ASSET_REGISTRY:
            if r["chain_ref"] == chain or r["chain"] == chain:
                family = r["family"]
                break
        addr = _mock_address(user, family, chain, chain)
        return {"address": addr}

    # -- vaults ------------------------------------------------------------
    def _ensure_vault(self, vault_id: str, name: str) -> Dict[str, Any]:
        if vault_id not in self._vaults:
            self._vaults[vault_id] = {
                "vault_id": vault_id,
                "name": name,
                "tier": "standard",
                "per_tx_cap": 50000.0,
                "daily_cap": 250000.0,
                "balances": {},
            }
        return self._vaults[vault_id]

    def seed_user_vault(self, vault_id: str, user: str) -> None:
        """Seed a few non-zero demo balances the first time we see a user."""
        with self._lock:
            if user in self._seeded_users:
                return
            v = self._ensure_vault(vault_id, f"{user} custody")
            # Deterministic-ish demo balances.
            v["balances"].setdefault("ETH", 2.5)
            v["balances"].setdefault("USDC", 5230.0)
            v["balances"].setdefault("USDT", 1200.0)
            v["balances"].setdefault("BTC", 0.15)
            v["balances"].setdefault("SOL", 42.0)
            self._seeded_users.add(user)
            self._append_audit("vault.seed", {"vault_id": vault_id})

    def create_vault(self, name: str) -> Dict[str, Any]:
        with self._lock:
            vault_id = f"{self._tenant}-v-{_derive_hex('vault', name, length=12)}"
            v = self._ensure_vault(vault_id, name)
            self._append_audit("vault.create", {"vault_id": vault_id})
            return dict(v)

    def list_vaults(self) -> Dict[str, Any]:
        with self._lock:
            return {"vaults": [dict(v) for v in self._vaults.values()]}

    def get_vault(self, vault_id: str) -> Dict[str, Any]:
        with self._lock:
            v = self._vaults.get(vault_id)
            return dict(v) if v else {}

    def credit_vault(self, vault_id: str, asset: str, amount: float) -> Dict[str, Any]:
        with self._lock:
            v = self._ensure_vault(vault_id, vault_id)
            v["balances"][asset] = float(v["balances"].get(asset, 0.0)) + float(amount)
            self._append_audit("vault.credit", {"vault_id": vault_id, "asset": asset, "amount": amount})
            return dict(v)

    def balance(self, vault_id: str, asset: str) -> float:
        with self._lock:
            v = self._vaults.get(vault_id)
            if not v:
                return 0.0
            return float(v["balances"].get(asset, 0.0))

    def debit_vault(self, vault_id: str, asset: str, amount: float) -> None:
        with self._lock:
            v = self._ensure_vault(vault_id, vault_id)
            v["balances"][asset] = max(0.0, float(v["balances"].get(asset, 0.0)) - float(amount))

    # -- withdrawals -------------------------------------------------------
    @staticmethod
    def _parse_intent(intent: str) -> Dict[str, Any]:
        parts = intent.split("|")
        keys = ["asset", "chain_ref", "network", "recipient", "amount", "ts_ms", "nonce"]
        out = dict(zip(keys, parts))
        try:
            out["amount"] = float(out.get("amount", "0"))
        except ValueError:
            out["amount"] = 0.0
        return out

    def create_withdrawal(self, wallet: str, intent: str, idempotency_key: str) -> Tuple[int, Dict[str, Any]]:
        with self._lock:
            if idempotency_key and idempotency_key in self._idem:
                wid = self._idem[idempotency_key]
                return self._status_tuple(wid)
            parsed = self._parse_intent(intent)
            wid = f"wd-{uuid.uuid4().hex[:16]}"
            recipient = str(parsed.get("recipient", ""))
            amount = float(parsed.get("amount", 0.0))
            asset = str(parsed.get("asset", ""))
            now = _now_ms()
            base = {
                "withdrawal_id": wid,
                "wallet_id": wallet,
                "asset": asset,
                "chain_ref": parsed.get("chain_ref"),
                "network": parsed.get("network"),
                "recipient": recipient,
                "amount": amount,
                "created_ms": now,
                "intent": intent,
                "approvals": [],
                "approvals_required": self._approvals_required,
            }
            # Screening / sanctions gate.
            if recipient.lower() in _MOCK_SANCTIONED:
                base["status"] = "blocked"
                base["error"] = "sanctioned_recipient"
                base["category"] = "ofac"
                base["source"] = "demo_list"
                self._withdrawals[wid] = base
                if idempotency_key:
                    self._idem[idempotency_key] = wid
                self._append_audit("withdrawal.blocked", {"withdrawal_id": wid, "recipient": recipient})
                return 403, {
                    "status": "blocked",
                    "error": "sanctioned_recipient",
                    "category": "ofac",
                    "source": "demo_list",
                    "withdrawal_id": wid,
                }
            if amount >= self._threshold:
                base["status"] = "pending_approval"
                base["timelock_until_ms"] = now + int(getattr(S, "custody_timelock_seconds", 0)) * 1000
                self._withdrawals[wid] = base
                if idempotency_key:
                    self._idem[idempotency_key] = wid
                self._append_audit("withdrawal.pending", {"withdrawal_id": wid, "amount": amount})
                return 202, {
                    "withdrawal_id": wid,
                    "status": "pending_approval",
                    "approvals_required": self._approvals_required,
                    "approvals": [],
                }
            # Below threshold -> screened + signed immediately.
            base["status"] = "signed"
            base["signature"] = "0x" + _derive_hex("sig", wid, intent, length=130)
            base["digest"] = "0x" + _derive_hex("digest", intent, length=64)
            base["signed_ms"] = now
            self._withdrawals[wid] = base
            if idempotency_key:
                self._idem[idempotency_key] = wid
            self._append_audit("withdrawal.signed", {"withdrawal_id": wid, "amount": amount})
            # Auto-progress signed -> broadcast -> settled deterministically for demo.
            return 200, {
                "withdrawal_id": wid,
                "wallet_id": wallet,
                "status": "signed",
                "signature": base["signature"],
                "digest": base["digest"],
            }

    def approve_withdrawal(self, withdrawal_id: str, approver: str) -> Tuple[int, Dict[str, Any]]:
        with self._lock:
            w = self._withdrawals.get(withdrawal_id)
            if not w:
                return 404, {"detail": "not_found"}
            if w["status"] not in ("pending_approval",):
                return 409, {"status": w["status"], "detail": "not_pending_approval"}
            if approver not in w["approvals"]:
                w["approvals"].append(approver)
                self._append_audit("withdrawal.approval", {"withdrawal_id": withdrawal_id, "approver": approver})
            if len(w["approvals"]) >= w["approvals_required"]:
                w["status"] = "approved"
                self._append_audit("withdrawal.approved", {"withdrawal_id": withdrawal_id})
            return 200, {
                "withdrawal_id": withdrawal_id,
                "status": w["status"],
                "approvals": list(w["approvals"]),
                "approvals_required": w["approvals_required"],
            }

    def release_withdrawal(self, withdrawal_id: str) -> Tuple[int, Dict[str, Any]]:
        with self._lock:
            w = self._withdrawals.get(withdrawal_id)
            if not w:
                return 404, {"detail": "not_found"}
            now = _now_ms()
            if now < int(w.get("timelock_until_ms", 0)):
                return 425, {"status": "timelock", "detail": "timelock_not_elapsed",
                             "timelock_until_ms": w.get("timelock_until_ms")}
            if len(w.get("approvals", [])) < w.get("approvals_required", self._approvals_required):
                return 409, {"status": w["status"], "detail": "insufficient_approvals"}
            w["signature"] = "0x" + _derive_hex("sig", withdrawal_id, w.get("intent", ""), length=130)
            w["digest"] = "0x" + _derive_hex("digest", w.get("intent", ""), length=64)
            w["status"] = "signed"
            w["signed_ms"] = now
            self._append_audit("withdrawal.released", {"withdrawal_id": withdrawal_id})
            return 200, {
                "withdrawal_id": withdrawal_id,
                "status": "signed",
                "signature": w["signature"],
                "digest": w["digest"],
            }

    def _effective_status(self, w: Dict[str, Any]) -> str:
        """Progress signed -> broadcast -> settled over wall-clock for demo realism."""
        status = w.get("status")
        if status == "signed":
            elapsed = _now_ms() - int(w.get("signed_ms", _now_ms()))
            if elapsed >= 4000:
                return "settled"
            if elapsed >= 1000:
                return "broadcast"
        return status

    def _status_tuple(self, withdrawal_id: str) -> Tuple[int, Dict[str, Any]]:
        w = self._withdrawals.get(withdrawal_id)
        if not w:
            return 404, {"detail": "not_found"}
        return 200, self.get_withdrawal(withdrawal_id)

    def get_withdrawal(self, withdrawal_id: str) -> Dict[str, Any]:
        with self._lock:
            w = self._withdrawals.get(withdrawal_id)
            if not w:
                return {}
            eff = self._effective_status(w)
            out = {
                "withdrawal_id": w["withdrawal_id"],
                "wallet_id": w["wallet_id"],
                "asset": w.get("asset"),
                "chain_ref": w.get("chain_ref"),
                "network": w.get("network"),
                "recipient": w.get("recipient"),
                "amount": w.get("amount"),
                "status": eff,
                "approvals": list(w.get("approvals", [])),
                "approvals_required": w.get("approvals_required"),
                "created_ms": w.get("created_ms"),
            }
            for k in ("signature", "digest", "error", "category", "source", "timelock_until_ms"):
                if k in w:
                    out[k] = w[k]
            return out

    def list_withdrawals(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self.get_withdrawal(wid) for wid in self._withdrawals]

    # -- audit -------------------------------------------------------------
    def audit(self) -> Dict[str, Any]:
        with self._lock:
            return {"entries": list(self._audit[-100:])}

    def audit_verify(self) -> Dict[str, Any]:
        with self._lock:
            prev = "0" * 64
            for e in self._audit:
                body = {"seq": e["seq"], "action": e["action"], "detail": e["detail"], "ts_ms": e["ts_ms"]}
                chained = hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
                if chained != e["hash"] or e["prev"] != prev:
                    return {"ok": False, "entries": len(self._audit)}
                prev = chained
            return {"ok": True, "entries": len(self._audit)}


# ---------------------------------------------------------------------------
# Module-level singletons.
# ---------------------------------------------------------------------------
_MOCK_SINGLETON: Optional[_MockCustodyGateway] = None
_REAL_SINGLETON: Optional[CustodyGatewayClient] = None


def _load_officer_keys() -> Dict[str, Dict[str, str]]:
    raw = getattr(S, "custody_officer_keys", "") or ""
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return {str(k): dict(v) for k, v in data.items() if isinstance(v, dict)}
    except Exception:
        logger.warning("CUSTODY_OFFICER_KEYS is not valid JSON; ignoring")
    return {}


def get_custody_gateway():
    """Return the real client when configured, else the shared in-memory mock."""
    global _MOCK_SINGLETON, _REAL_SINGLETON
    if CustodyGatewayClient.is_configured():
        if _REAL_SINGLETON is None:
            _REAL_SINGLETON = CustodyGatewayClient(
                base_url=S.custody_gateway_url,
                api_key=S.custody_api_key,
                api_secret=S.custody_api_secret,
                tenant=S.custody_tenant,
                verify_tls=bool(S.custody_verify_tls),
                timeout_seconds=float(S.custody_timeout_seconds),
                officer_keys=_load_officer_keys(),
            )
        return _REAL_SINGLETON
    if _MOCK_SINGLETON is None:
        _MOCK_SINGLETON = _MockCustodyGateway(tenant=S.custody_tenant)
    return _MOCK_SINGLETON


def is_mock(gateway: Any) -> bool:
    return isinstance(gateway, _MockCustodyGateway)
