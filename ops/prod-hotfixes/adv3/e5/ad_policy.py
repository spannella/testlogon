"""Automated ad-content policy pass (ADV3-11 / E1).

Every piece of ad creative (standalone creative, seller-boost product ad,
sponsored-as-creator post body, sponsored-message body) is screened by
``screen_creative`` BEFORE it can serve/publish. The pass is deterministic and
synchronous so it is fully testable and can run inline on the submit path.

Three-way decision:
  * ``reject``  -- a HARD violation (deny-listed term, prohibited category, or a
                   bad/blocked landing domain). Auto-rejected before a human sees
                   it (AC: "auto-rejected or hard-flagged before a human").
  * ``review``  -- soft/risk signals (profanity, scam-adjacent tokens, a non-HTTPS
                   or URL-shortener landing, missing landing for a CTA). Held in
                   ``pending_review`` and RISK-RANKED by ``score`` for the admin
                   queue.
  * ``clean``   -- no signal. (Callers that want a human in the loop still route a
                   clean result to ``pending_review``; self-serve callers such as
                   seller-boost may auto-approve a clean result.)

The pass reuses the existing keyword ``content_filter`` deny-list for profanity
and layers ad-specific prohibited terms/categories + a landing-URL/domain
reputation check on top. No ad text/URL reaches serve without a pass.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Hard-violation deny-list (auto-reject) ──────────────────────────────────
# Scam / malware / illegal-goods / regulated-goods terms an ad may never carry.
# Matched case-insensitively on word boundaries against the combined ad text.
PROHIBITED_TERMS: List[str] = [
    # financial / scam
    "guaranteed returns", "risk-free investment", "double your money",
    "get rich quick", "wire transfer only", "nigerian prince", "ponzi",
    "pump and dump", "crypto giveaway", "forex signals guaranteed",
    # malware / fraud
    "free gift card", "you won", "claim your prize", "verify your account now",
    "phishing", "malware", "keylogger", "carding", "stolen cards",
    # illegal / regulated goods
    "buy cocaine", "buy heroin", "sell drugs", "counterfeit", "fake passport",
    "child porn", "cp for sale", "buy followers cheap", "human trafficking",
    "unregistered firearms", "buy guns no license",
]

# Prohibited advertiser categories (campaign.category / creative category).
PROHIBITED_CATEGORIES = frozenset({
    "adult", "gambling_illegal", "weapons", "drugs", "counterfeit",
    "hate", "malware", "tobacco_minors",
})

# Landing domains that may never be advertised.
BLOCKED_DOMAINS = frozenset({
    "example-malware.com", "phishing.test", "free-giftcards.win",
    "bit.ly.malware", "malware.test", "scam.test",
})

# URL shorteners hide the true landing -> a soft risk signal (not a hard block).
URL_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at",
})

# Soft risk tokens (profanity-adjacent / spammy) -> risk score, not auto-reject.
RISK_TERMS: List[str] = [
    "act now", "limited time", "100% free", "no credit check", "miracle",
    "cure", "weight loss", "as seen on tv", "click here", "winner",
]

_WORD = lambda terms: re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(t) for t in terms) + r")(?![a-z0-9])",
    re.IGNORECASE,
)
_PROHIBITED_RE = _WORD(PROHIBITED_TERMS)
_RISK_RE = _WORD(RISK_TERMS)
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Risk-score weights (out of 100). >= HARD_REJECT_SCORE is a hard reject even
# without an explicit deny-list hit; >= REVIEW_SCORE lands in the risk-ranked
# admin queue. Any explicit prohibited-term/category/blocked-domain hit is an
# unconditional reject regardless of score.
HARD_REJECT_SCORE = 80
REVIEW_SCORE = 20
_W_RISK_TERM = 10
_W_SHORTENER = 15
_W_NON_HTTPS = 15
_W_NO_TLD = 25


class PolicyResult:
    def __init__(
        self, *, decision: str, score: int,
        reasons: List[str], matched: List[str], flags: List[str],
    ) -> None:
        self.decision = decision      # "clean" | "review" | "reject"
        self.score = score
        self.reasons = reasons
        self.matched = matched
        self.flags = flags

    @property
    def hard_violation(self) -> bool:
        return self.decision == "reject"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_decision": self.decision,
            "policy_score": self.score,
            "policy_reasons": self.reasons,
            "policy_matched": self.matched,
            "policy_flags": self.flags,
        }


def _domain(url: str) -> str:
    try:
        netloc = urlparse(url.strip()).netloc.lower()
    except Exception:
        return ""
    if "@" in netloc:
        netloc = netloc.split("@", 1)[1]
    return netloc.split(":", 1)[0]


def _screen_text(text: str) -> Dict[str, Any]:
    """Scan a text blob; returns hard prohibited hits + soft risk hits."""
    t = text or ""
    prohibited = sorted({m.group(1).lower() for m in _PROHIBITED_RE.finditer(t)})
    risk = sorted({m.group(1).lower() for m in _RISK_RE.finditer(t)})
    # Reuse the platform profanity deny-list (soft signal on an ad).
    profane = False
    try:
        from app.services.content_filter import filter_message
        _, profane = filter_message(t)
    except Exception:
        profane = False
    return {"prohibited": prohibited, "risk": risk, "profane": bool(profane)}


def screen_url(url: str) -> Dict[str, Any]:
    """Landing-URL / domain reputation check. Returns hard/soft signals."""
    url = (url or "").strip()
    if not url:
        return {"empty": True}
    dom = _domain(url)
    is_https = url.lower().startswith("https://")
    if not dom or "." not in dom:
        # A CTA/landing without a resolvable host is a hard signal (broken/opaque).
        return {"url": url, "domain": dom, "no_tld": True}
    if dom in BLOCKED_DOMAINS or any(dom == b or dom.endswith("." + b) for b in BLOCKED_DOMAINS):
        return {"url": url, "domain": dom, "blocked": True}
    signals: Dict[str, Any] = {"url": url, "domain": dom}
    if dom in URL_SHORTENER_DOMAINS:
        signals["shortener"] = True
    if not is_https:
        signals["non_https"] = True
    return signals


def screen_creative(
    *,
    title: str = "",
    headline: str = "",
    body_text: str = "",
    cta_text: str = "",
    cta_url: str = "",
    category: str = "",
    extra_urls: Optional[List[str]] = None,
) -> PolicyResult:
    """Run the automated ad-policy pass over one creative's text + URLs.

    Returns a :class:`PolicyResult` with a three-way decision + a 0-100 risk
    score used to rank the admin review queue.
    """
    reasons: List[str] = []
    matched: List[str] = []
    flags: List[str] = []
    score = 0
    hard = False

    combined = " \n ".join(str(x or "") for x in (title, headline, body_text, cta_text))
    txt = _screen_text(combined)
    if txt["prohibited"]:
        hard = True
        matched.extend(txt["prohibited"])
        flags.append("prohibited_term")
        reasons.append("Prohibited term(s): %s" % ", ".join(txt["prohibited"]))
    if txt["risk"]:
        score += _W_RISK_TERM * len(txt["risk"])
        matched.extend(txt["risk"])
        flags.append("risk_term")
        reasons.append("Risk term(s): %s" % ", ".join(txt["risk"]))
    if txt["profane"]:
        score += _W_RISK_TERM
        flags.append("profanity")
        reasons.append("Profanity detected in ad copy")

    cat = str(category or "").strip().lower()
    if cat and cat in PROHIBITED_CATEGORIES:
        hard = True
        flags.append("prohibited_category")
        reasons.append("Prohibited category: %s" % cat)

    # URLs: the explicit CTA landing + any URL embedded in the copy.
    urls: List[str] = []
    if cta_url:
        urls.append(cta_url)
    urls.extend(extra_urls or [])
    urls.extend(_URL_RE.findall(combined))
    seen_dom: set = set()
    for u in urls:
        sig = screen_url(u)
        dom = sig.get("domain", "")
        if dom and dom in seen_dom:
            continue
        if dom:
            seen_dom.add(dom)
        if sig.get("blocked"):
            hard = True
            flags.append("blocked_domain")
            reasons.append("Blocked landing domain: %s" % dom)
        if sig.get("no_tld"):
            score += _W_NO_TLD
            flags.append("bad_landing_url")
            reasons.append("Landing URL has no resolvable domain: %s" % sig.get("url", ""))
        if sig.get("shortener"):
            score += _W_SHORTENER
            flags.append("url_shortener")
            reasons.append("Landing uses a URL shortener: %s" % dom)
        if sig.get("non_https"):
            score += _W_NON_HTTPS
            flags.append("non_https")
            reasons.append("Landing URL is not HTTPS: %s" % dom)

    score = min(int(score), 100)
    if hard or score >= HARD_REJECT_SCORE:
        decision = "reject"
    elif score >= REVIEW_SCORE:
        decision = "review"
    else:
        decision = "clean"

    # dedupe preserving order
    flags = list(dict.fromkeys(flags))
    matched = list(dict.fromkeys(matched))
    return PolicyResult(
        decision=decision, score=score, reasons=reasons, matched=matched, flags=flags,
    )


def screen_text_blob(text: str) -> PolicyResult:
    """Convenience wrapper for a single free-text body (sponsored post/message)."""
    return screen_creative(body_text=text)


def screen_creative_row(creative: Dict[str, Any]) -> PolicyResult:
    """Screen a persisted ad_creatives row (used at submit-for-review)."""
    return screen_creative(
        title=str(creative.get("title", "") or ""),
        headline=str(creative.get("headline", "") or ""),
        body_text=str(creative.get("body_text", "") or ""),
        cta_text=str(creative.get("cta_text", "") or ""),
        cta_url=str(creative.get("cta_url", "") or ""),
        category=str(creative.get("category", "") or ""),
    )
