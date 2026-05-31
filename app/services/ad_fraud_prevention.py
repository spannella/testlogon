"""Ad fraud prevention service (ADS-014).

Rule-based fraud detection for ad impressions, clicks, and completions.
Each rule contributes a score (0-100). Events scoring >= FRAUD_THRESHOLD are
flagged as fraudulent, recorded for admin review, and excluded from billing
(no advertiser charge, no creator credit).

All rules are deterministic and synchronous so behaviour is fully testable.
Counters use DynamoDB atomic updates with TTL and fail OPEN (a counter error
allows the event) so fraud detection cannot become a DoS vector.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

# ─── Thresholds & rule weights ───────────────────────────────────────────────

FRAUD_THRESHOLD = 70

# Auto-suspend an account once its rolling fraud rate crosses this (basis points).
AUTO_SUSPEND_FRAUD_RATE_BPS = 2000  # 20%

WEIGHT_CLICK_VELOCITY = 25
WEIGHT_IP_CLUSTERING = 25
WEIGHT_BOT_UA = 20
WEIGHT_IVT = 15
WEIGHT_CTR_ANOMALY = 10
WEIGHT_GEO_MISMATCH = 5

CLICK_VELOCITY_LIMIT = 5      # > 5 events / user / creative / 60s
IP_CLUSTER_LIMIT = 50         # > 50 events / ip / 5m
IVT_MIN_VIEW_MS = 1000        # complete events with < 1s view time
CTR_ANOMALY_PCT = 30.0        # campaign CTR above this is anomalous

RISK_WINDOW_SECONDS = 7 * 86400  # 7 days for rolling fraud-rate

# ─── Bot user-agent patterns (extended from affiliate_links.py) ──────────────

BOT_UA_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"bot", r"crawler", r"spider", r"scraper",
        r"headless", r"phantom", r"selenium", r"puppeteer",
        r"wget", r"curl/", r"python-requests", r"go-http-client",
        r"httpclient", r"java/", r"apache-httpclient",
    ]
]


def _date_str(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _ddb_safe(value: Any) -> Any:
    """Recursively convert Python floats to Decimal (boto3 rejects floats)."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _ddb_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_ddb_safe(v) for v in value]
    return value


# ─── Result container ────────────────────────────────────────────────────────


class FraudCheckResult:
    def __init__(
        self,
        *,
        score: int,
        flagged: bool,
        rule_scores: Dict[str, int],
        details: Dict[str, Any],
    ) -> None:
        self.score = score
        self.flagged = flagged
        self.rule_scores = rule_scores
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fraud_score": self.score,
            "flagged": self.flagged,
            "rule_scores": self.rule_scores,
            "details": self.details,
        }


# ─── Top-level fraud check ───────────────────────────────────────────────────


def check_fraud(
    *,
    user_id: str,
    ip_address: str = "",
    user_agent: str = "",
    creative_id: str = "",
    campaign_id: str = "",
    view_time_ms: int = 0,
    event_type: str = "impression",
    geo_country: str = "",
    targeting_countries: Optional[List[str]] = None,
    count_velocity: bool = True,
) -> FraudCheckResult:
    """Run all six fraud rules against an ad event.

    ``count_velocity`` controls whether the velocity/IP counters are
    incremented (set False for read-only re-evaluation).
    """
    rule_scores: Dict[str, int] = {}
    details: Dict[str, Any] = {}
    total = 0

    vel_score, vel_detail = _check_click_velocity(
        user_id=user_id, creative_id=creative_id, count=count_velocity
    )
    rule_scores["click_velocity"] = vel_score
    details["click_velocity"] = vel_detail
    total += vel_score

    ip_score, ip_detail = _check_ip_clustering(
        ip_address=ip_address, count=count_velocity
    )
    rule_scores["ip_clustering"] = ip_score
    details["ip_clustering"] = ip_detail
    total += ip_score

    bot_score, bot_detail = _check_bot_ua(user_agent=user_agent)
    rule_scores["bot_ua"] = bot_score
    details["bot_ua"] = bot_detail
    total += bot_score

    ivt_score, ivt_detail = _check_ivt(view_time_ms=view_time_ms, event_type=event_type)
    rule_scores["ivt"] = ivt_score
    details["ivt"] = ivt_detail
    total += ivt_score

    ctr_score, ctr_detail = _check_ctr_anomaly(campaign_id=campaign_id)
    rule_scores["ctr_anomaly"] = ctr_score
    details["ctr_anomaly"] = ctr_detail
    total += ctr_score

    geo_score, geo_detail = _check_geo_mismatch(
        geo_country=geo_country,
        targeting_countries=targeting_countries or [],
    )
    rule_scores["geo_mismatch"] = geo_score
    details["geo_mismatch"] = geo_detail
    total += geo_score

    total = min(total, 100)
    flagged = total >= FRAUD_THRESHOLD

    return FraudCheckResult(
        score=total, flagged=flagged, rule_scores=rule_scores, details=details
    )


# ─── Individual rules ────────────────────────────────────────────────────────


def _check_click_velocity(
    *, user_id: str, creative_id: str, count: bool = True
) -> Tuple[int, Dict[str, Any]]:
    """> CLICK_VELOCITY_LIMIT events / same user / same creative / 60s window."""
    if not user_id or not creative_id:
        return 0, {"skipped": True}
    ts = now_ts()
    minute_bucket = ts // 60
    pk = f"VEL#{user_id}"
    sk = f"CR#{creative_id}#{minute_bucket}"

    try:
        if count:
            resp = T.ad_fraud_events.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET #cnt = if_not_exists(#cnt, :z) + :one, #ttl = :ttl",
                ExpressionAttributeNames={"#cnt": "event_count", "#ttl": "ttl"},
                ExpressionAttributeValues={":z": 0, ":one": 1, ":ttl": ts + 120},
                ReturnValues="UPDATED_NEW",
            )
            cnt = _to_int(resp["Attributes"]["event_count"])
        else:
            item = T.ad_fraud_events.get_item(Key={"pk": pk, "sk": sk}).get("Item") or {}
            cnt = _to_int(item.get("event_count", 0))
    except Exception:
        return 0, {"error": "velocity_check_failed"}

    if cnt > CLICK_VELOCITY_LIMIT:
        return WEIGHT_CLICK_VELOCITY, {"events_in_window": cnt, "threshold": CLICK_VELOCITY_LIMIT}
    return 0, {"events_in_window": cnt, "threshold": CLICK_VELOCITY_LIMIT}


def _check_ip_clustering(
    *, ip_address: str, count: bool = True
) -> Tuple[int, Dict[str, Any]]:
    """> IP_CLUSTER_LIMIT events / same IP / 5m window."""
    if not ip_address:
        return 0, {"skipped": True}
    ts = now_ts()
    bucket = ts // 300
    pk = f"IP#{ip_address}"
    sk = f"BUCKET#{bucket}"

    try:
        if count:
            resp = T.ad_fraud_events.update_item(
                Key={"pk": pk, "sk": sk},
                UpdateExpression="SET #cnt = if_not_exists(#cnt, :z) + :one, #ttl = :ttl",
                ExpressionAttributeNames={"#cnt": "event_count", "#ttl": "ttl"},
                ExpressionAttributeValues={":z": 0, ":one": 1, ":ttl": ts + 600},
                ReturnValues="UPDATED_NEW",
            )
            cnt = _to_int(resp["Attributes"]["event_count"])
        else:
            item = T.ad_fraud_events.get_item(Key={"pk": pk, "sk": sk}).get("Item") or {}
            cnt = _to_int(item.get("event_count", 0))
    except Exception:
        return 0, {"error": "ip_check_failed"}

    if cnt > IP_CLUSTER_LIMIT:
        return WEIGHT_IP_CLUSTERING, {"events_in_window": cnt, "threshold": IP_CLUSTER_LIMIT}
    return 0, {"events_in_window": cnt, "threshold": IP_CLUSTER_LIMIT}


def _check_bot_ua(*, user_agent: str) -> Tuple[int, Dict[str, Any]]:
    """Known bot / automation user-agent patterns."""
    ua = user_agent or ""
    for pattern in BOT_UA_PATTERNS:
        if pattern.search(ua):
            return WEIGHT_BOT_UA, {
                "matched_pattern": pattern.pattern,
                "user_agent": ua[:120],
            }
    return 0, {"bot_detected": False}


def _check_ivt(*, view_time_ms: int, event_type: str) -> Tuple[int, Dict[str, Any]]:
    """Invalid traffic: 'complete' events with view time under 1 second."""
    if event_type != "complete":
        return 0, {"skipped": True, "reason": "not_complete_event"}
    vt = _to_int(view_time_ms)
    if vt < IVT_MIN_VIEW_MS:
        return WEIGHT_IVT, {"view_time_ms": vt, "threshold_ms": IVT_MIN_VIEW_MS}
    return 0, {"view_time_ms": vt, "threshold_ms": IVT_MIN_VIEW_MS}


def _check_ctr_anomaly(*, campaign_id: str) -> Tuple[int, Dict[str, Any]]:
    """Campaign click-through rate above CTR_ANOMALY_PCT (industry avg ~2%)."""
    if not campaign_id:
        return 0, {"skipped": True}
    try:
        from app.services.ad_serving import get_serving_stats

        stats = get_serving_stats(campaign_id)
        ctr = float(stats.get("ctr_pct", 0.0))
        impressions = _to_int(stats.get("impressions", 0))
    except Exception:
        return 0, {"ctr_check": "failed"}

    # Need a minimum sample before flagging.
    if impressions >= 10 and ctr > CTR_ANOMALY_PCT:
        return WEIGHT_CTR_ANOMALY, {"ctr_pct": ctr, "threshold_pct": CTR_ANOMALY_PCT}
    return 0, {"ctr_pct": ctr, "threshold_pct": CTR_ANOMALY_PCT}


def _check_geo_mismatch(
    *, geo_country: str, targeting_countries: List[str]
) -> Tuple[int, Dict[str, Any]]:
    """Click from a country not in the campaign targeting."""
    if not targeting_countries or not geo_country:
        return 0, {"geo_check": "no_targeting_or_geo"}
    allowed = {c.upper() for c in targeting_countries}
    if geo_country.upper() not in allowed:
        return WEIGHT_GEO_MISMATCH, {
            "user_country": geo_country,
            "targeting_countries": targeting_countries,
        }
    return 0, {"geo_match": True}


# ─── Fraud-event recording ───────────────────────────────────────────────────


def record_fraud_event(
    *,
    event_id: str,
    user_id: str,
    ip_address: str,
    account_id: str,
    campaign_id: str,
    creative_id: str,
    event_type: str,
    fraud_result: FraudCheckResult,
    status: str = "flagged",
) -> Dict[str, Any]:
    """Persist a flagged fraud event for admin review.

    Always records an account-rollup counter so risk/fraud-rate is cheap to read.
    """
    ts = now_ts()
    date_str = _date_str(ts)
    acct = account_id or "unknown"

    item = {
        "pk": f"FRAUD#{date_str}",
        "sk": f"EVENT#{ts}#{event_id}",
        "event_id": event_id,
        "user_id": user_id,
        "ip_address": ip_address,
        "account_id": acct,
        "campaign_id": campaign_id,
        "creative_id": creative_id,
        "event_type": event_type,
        "fraud_score": int(fraud_result.score),
        "rule_scores": _ddb_safe(fraud_result.rule_scores),
        "details": _ddb_safe(fraud_result.details),
        "status": status,
        "created_at": ts,
        "GSI1PK": f"ACCOUNT#{acct}",
        "GSI1SK": ts,
        "GSI2PK": f"CAMPAIGN#{campaign_id or 'unknown'}",
        "GSI2SK": ts,
    }
    try:
        T.ad_fraud_events.put_item(Item=item)
    except Exception:
        logger.warning("ad_fraud_event_write_failed event_id=%s", event_id)

    _bump_account_counters(account_id=acct, ts=ts, flagged=True)
    return item


def record_account_activity(*, account_id: str, flagged: bool) -> None:
    """Record a (legitimate or flagged) ad event in the account rollup."""
    if not account_id:
        return
    _bump_account_counters(account_id=account_id, ts=now_ts(), flagged=flagged)


def _bump_account_counters(*, account_id: str, ts: int, flagged: bool) -> None:
    if not account_id:
        return
    try:
        T.ad_fraud_events.update_item(
            Key={"pk": f"RISK#{account_id}", "sk": "META"},
            UpdateExpression=(
                "SET account_id = :aid, last_event_at = :ts, "
                "total_events = if_not_exists(total_events, :z) + :one, "
                "flagged_events = if_not_exists(flagged_events, :z) + :f"
                + (", last_fraud_event_at = :ts" if flagged else "")
            ),
            ExpressionAttributeValues={
                ":aid": account_id,
                ":ts": ts,
                ":z": 0,
                ":one": 1,
                ":f": 1 if flagged else 0,
            },
        )
    except Exception:
        logger.warning("ad_fraud_account_counter_failed account_id=%s", account_id)


# ─── Account risk / suspension ───────────────────────────────────────────────


def _risk_meta(account_id: str) -> Dict[str, Any]:
    try:
        item = T.ad_fraud_events.get_item(
            Key={"pk": f"RISK#{account_id}", "sk": "META"}
        ).get("Item")
        return item or {}
    except Exception:
        return {}


def _fraud_rate_bps(total: int, flagged: int) -> int:
    if total <= 0:
        return 0
    return int((flagged * 10000) // total)


def get_account_risk(account_id: str) -> Dict[str, Any]:
    """Risk summary for a single advertiser account."""
    from app.services.ad_accounts import get_ad_account

    meta = _risk_meta(account_id)
    total = _to_int(meta.get("total_events", 0))
    flagged = _to_int(meta.get("flagged_events", 0))
    acct = get_ad_account(account_id)
    status = acct.get("status", "unknown") if acct else "unknown"

    return {
        "account_id": account_id,
        "fraud_rate_bps": _fraud_rate_bps(total, flagged),
        "total_events": total,
        "flagged_events": flagged,
        "status": status,
        "last_fraud_event_at": _to_int(meta.get("last_fraud_event_at", 0)) or None,
        "last_event_at": _to_int(meta.get("last_event_at", 0)) or None,
    }


def get_account_risk_scores() -> List[Dict[str, Any]]:
    """Risk scores for all accounts that have ad-fraud activity (admin dashboard)."""
    from app.services.ad_accounts import get_ad_account

    out: List[Dict[str, Any]] = []
    try:
        resp = T.ad_fraud_events.scan(
            FilterExpression=Key("sk").eq("META"),
        )
        items = resp.get("Items", [])
    except Exception:
        items = []

    for it in items:
        pk = str(it.get("pk", ""))
        if not pk.startswith("RISK#"):
            continue
        account_id = it.get("account_id") or pk[len("RISK#"):]
        total = _to_int(it.get("total_events", 0))
        flagged = _to_int(it.get("flagged_events", 0))
        acct = get_ad_account(account_id)
        status = acct.get("status", "unknown") if acct else "unknown"
        out.append({
            "account_id": account_id,
            "fraud_rate_bps": _fraud_rate_bps(total, flagged),
            "total_events": total,
            "flagged_events": flagged,
            "status": status,
            "last_fraud_event_at": _to_int(it.get("last_fraud_event_at", 0)) or None,
            "last_event_at": _to_int(it.get("last_event_at", 0)) or None,
        })

    out.sort(key=lambda r: r["fraud_rate_bps"], reverse=True)
    return out


def maybe_auto_suspend(*, account_id: str) -> Dict[str, Any]:
    """Auto-suspend an account whose rolling fraud rate exceeds the threshold."""
    if not account_id:
        return {"suspended": False}

    meta = _risk_meta(account_id)
    total = _to_int(meta.get("total_events", 0))
    flagged = _to_int(meta.get("flagged_events", 0))
    rate_bps = _fraud_rate_bps(total, flagged)
    threshold = getattr(S, "ad_fraud_auto_suspend_rate_bps", AUTO_SUSPEND_FRAUD_RATE_BPS)

    # Require a minimum sample so a single flagged event on a new account
    # doesn't auto-suspend it.
    if total < 5 or rate_bps < threshold:
        return {"suspended": False, "fraud_rate_bps": rate_bps}

    suspend_account(account_id=account_id, actor="system", reason="auto_suspend_fraud_rate")
    return {"suspended": True, "fraud_rate_bps": rate_bps}


def suspend_account(*, account_id: str, actor: str, reason: str = "") -> Dict[str, Any]:
    """Set an advertiser account to 'suspended'."""
    ts = now_ts()
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression=(
                "SET #s = :s, fraud_suspended_at = :ts, fraud_suspended_by = :actor, "
                "fraud_suspend_reason = :reason, updated_at = :ts"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "suspended",
                ":ts": ts,
                ":actor": actor,
                ":reason": reason,
            },
        )
    except Exception:
        logger.warning("ad_fraud_suspend_failed account_id=%s", account_id)
        return {"ok": False, "account_id": account_id}

    try:
        T.ad_fraud_events.update_item(
            Key={"pk": f"RISK#{account_id}", "sk": "META"},
            UpdateExpression="SET account_id = :aid, suspended = :t, suspended_at = :ts",
            ExpressionAttributeValues={":aid": account_id, ":t": True, ":ts": ts},
        )
    except Exception:
        pass

    return {"ok": True, "account_id": account_id, "status": "suspended"}


def unsuspend_account(*, account_id: str, actor: str) -> Dict[str, Any]:
    """Restore a suspended advertiser account to 'active'."""
    ts = now_ts()
    try:
        T.ad_accounts.update_item(
            Key={"pk": f"ACCT#{account_id}", "sk": "META"},
            UpdateExpression=(
                "SET #s = :s, fraud_unsuspended_at = :ts, fraud_unsuspended_by = :actor, "
                "updated_at = :ts"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "active", ":ts": ts, ":actor": actor},
        )
    except Exception:
        logger.warning("ad_fraud_unsuspend_failed account_id=%s", account_id)
        return {"ok": False, "account_id": account_id}

    try:
        T.ad_fraud_events.update_item(
            Key={"pk": f"RISK#{account_id}", "sk": "META"},
            UpdateExpression="SET account_id = :aid, suspended = :f, unsuspended_at = :ts",
            ExpressionAttributeValues={":aid": account_id, ":f": False, ":ts": ts},
        )
    except Exception:
        pass

    return {"ok": True, "account_id": account_id, "status": "active"}


def is_account_suspended(account_id: str) -> bool:
    from app.services.ad_accounts import get_ad_account

    acct = get_ad_account(account_id)
    return bool(acct) and acct.get("status") == "suspended"


# ─── Admin dashboard reads ───────────────────────────────────────────────────


def list_fraud_events(
    *, date: str = "", limit: int = 100
) -> List[Dict[str, Any]]:
    """List flagged fraud events, newest first.

    Defaults to today's partition; pass an explicit ``date`` (YYYY-MM-DD) to
    page through a specific day.
    """
    date_str = date or _date_str(now_ts())
    try:
        resp = T.ad_fraud_events.query(
            KeyConditionExpression=Key("pk").eq(f"FRAUD#{date_str}")
            & Key("sk").begins_with("EVENT#"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return resp.get("Items", [])
    except Exception:
        logger.warning("ad_fraud_list_failed date=%s", date_str)
        return []


def get_fraud_event(event_id: str) -> Optional[Dict[str, Any]]:
    """Look up a single fraud event by id (scans today + recent partitions)."""
    ts = now_ts()
    for days_back in range(0, 8):
        date_str = _date_str(ts - days_back * 86400)
        try:
            resp = T.ad_fraud_events.query(
                KeyConditionExpression=Key("pk").eq(f"FRAUD#{date_str}")
                & Key("sk").begins_with("EVENT#"),
            )
        except Exception:
            continue
        for it in resp.get("Items", []):
            if it.get("event_id") == event_id:
                return it
    return None


def list_fraud_events_for_account(account_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    try:
        resp = T.ad_fraud_events.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("GSI1PK").eq(f"ACCOUNT#{account_id}"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return resp.get("Items", [])
    except Exception:
        return []


def review_fraud_event(*, event_id: str, decision: str, actor: str) -> Optional[Dict[str, Any]]:
    """Admin confirm/dismiss a flagged event.

    decision: 'confirm' -> status='confirmed'; 'dismiss' -> status='dismissed'.
    """
    new_status = "confirmed" if decision == "confirm" else "dismissed"
    ev = get_fraud_event(event_id)
    if not ev:
        return None
    try:
        T.ad_fraud_events.update_item(
            Key={"pk": ev["pk"], "sk": ev["sk"]},
            UpdateExpression="SET #s = :s, reviewed_by = :a, reviewed_at = :ts",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": new_status, ":a": actor, ":ts": now_ts()},
        )
    except Exception:
        logger.warning("ad_fraud_review_failed event_id=%s", event_id)
        return None
    ev["status"] = new_status
    ev["reviewed_by"] = actor
    return ev


def get_fraud_summary() -> Dict[str, Any]:
    """Aggregate today's fraud stats + account/risk rollups for the dashboard."""
    today = list_fraud_events(date=_date_str(now_ts()), limit=1000)

    flagged_today = len(today)
    rule_counts: Dict[str, int] = {}
    for ev in today:
        rs = ev.get("rule_scores") or {}
        for rule, score in rs.items():
            if _to_int(score) > 0:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

    risks = get_account_risk_scores()
    total_events = sum(r["total_events"] for r in risks)
    flagged_events = sum(r["flagged_events"] for r in risks)
    suspended = sum(1 for r in risks if r["status"] == "suspended")

    return {
        "flagged_events_today": flagged_today,
        "total_events": total_events,
        "flagged_events": flagged_events,
        "fraud_rate_bps": _fraud_rate_bps(total_events, flagged_events),
        "suspended_accounts": suspended,
        "tracked_accounts": len(risks),
        "top_fraud_rules": rule_counts,
    }
