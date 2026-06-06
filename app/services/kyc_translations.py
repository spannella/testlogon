"""KYC-020: Multi-Language Support — KYC translation store + localization.

A self-contained KYC translation layer built ON TOP of the existing platform
i18n module (``app/i18n``).  We reuse the platform's locale-resolution
conventions (profile.locale > Accept-Language > default) but keep KYC strings
in a dedicated ``kyc_translations`` DynamoDB table so that admins can manage
KYC content independently and so that coverage reporting is scoped to KYC keys.

Storage model (see KYC-020 §4.1):

    Table: kyc_translations
      PK: language_code (S)   — e.g. "es", "fr"
      SK: key (S)             — e.g. "kyc.status.approved"
      value (S), context (S), status (S), updated_by (S), updated_at (N)
      GSI status-language-index: PK=status, SK=language_code

Resolution falls back to English when a key is missing for the requested
locale, then to the supplied fallback, then to the key itself.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from boto3.dynamodb.conditions import Key

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)

_KEY_PREFIX = "kyc."
_VALID_STATUSES = {"published", "draft", "needs_review"}
_BATCH_GET_CHUNK = 100  # DynamoDB BatchGetItem hard limit (max 100 keys/call)

# Locale display metadata.  Mirrors the platform i18n metadata but extended to
# cover all KYC-supported locales (KYC-020 §1.2).
_LOCALE_METADATA: Dict[str, Dict[str, Any]] = {
    "en": {"name": "English", "native_name": "English", "rtl": False},
    "es": {"name": "Spanish", "native_name": "Español", "rtl": False},
    "fr": {"name": "French", "native_name": "Français", "rtl": False},
    "de": {"name": "German", "native_name": "Deutsch", "rtl": False},
    "pt": {"name": "Portuguese", "native_name": "Português", "rtl": False},
    "zh": {"name": "Chinese (Simplified)", "native_name": "简体中文", "rtl": False},
    "ja": {"name": "Japanese", "native_name": "日本語", "rtl": False},
    "ko": {"name": "Korean", "native_name": "한국어", "rtl": False},
    "ar": {"name": "Arabic", "native_name": "العربية", "rtl": True},
    "hi": {"name": "Hindi", "native_name": "हिन्दी", "rtl": False},
}

_RTL_LOCALES = {code for code, meta in _LOCALE_METADATA.items() if meta["rtl"]}


class UnsupportedLocaleError(Exception):
    """Raised when a locale code is not in the supported set."""


class KycTranslationService:
    """Translation store + localization helpers for KYC content."""

    # ── locale helpers ───────────────────────────────────────────────

    def supported_locales(self) -> List[str]:
        raw = getattr(S, "i18n_kyc_supported_locales", "") or "en"
        return [c.strip() for c in raw.split(",") if c.strip()]

    def default_locale(self) -> str:
        return getattr(S, "i18n_kyc_default_locale", "en") or "en"

    def is_supported(self, locale: Optional[str]) -> bool:
        return bool(locale) and locale in self.supported_locales()

    def is_rtl(self, locale: str) -> bool:
        return locale in _RTL_LOCALES

    def locale_descriptors(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for code in self.supported_locales():
            meta = _LOCALE_METADATA.get(code, {"name": code, "native_name": code, "rtl": False})
            out.append(
                {
                    "code": code,
                    "name": meta["name"],
                    "native_name": meta["native_name"],
                    "rtl": meta["rtl"],
                }
            )
        return out

    def normalize_locale(self, locale: Optional[str]) -> str:
        """Return the locale if supported, else the default locale (English)."""
        if locale and self.is_supported(locale):
            return locale
        return self.default_locale()

    def resolve_locale(
        self,
        *,
        user_profile: Optional[Dict[str, Any]] = None,
        accept_language: Optional[str] = None,
    ) -> str:
        """Determine the effective locale: profile.locale > Accept-Language > default."""
        if user_profile:
            prof_locale = user_profile.get("locale")
            if prof_locale and self.is_supported(prof_locale):
                return prof_locale
        if accept_language:
            for part in accept_language.split(","):
                tag = part.split(";")[0].strip().split("-")[0].lower()
                if tag and self.is_supported(tag):
                    return tag
        return self.default_locale()

    def resolve_locale_for_user(
        self, user_sub: str, *, accept_language: Optional[str] = None
    ) -> str:
        """Resolve a user's KYC locale by loading their profile."""
        profile: Dict[str, Any] = {}
        try:
            from app.services import profile as profile_svc

            profile = profile_svc.get_profile(user_sub) or {}
        except Exception:
            profile = {}
        return self.resolve_locale(user_profile=profile, accept_language=accept_language)

    # ── core store access ────────────────────────────────────────────

    def _get_item(self, *, language: str, key: str) -> Optional[Dict[str, Any]]:
        try:
            resp = T.kyc_translations.get_item(Key={"language_code": language, "key": key})
        except Exception:
            return None
        return resp.get("Item")

    def translate(self, *, key: str, language: str, fallback: Optional[str] = None) -> str:
        """Look up a translation. Falls back to English, then ``fallback``, then ``key``."""
        item = self._get_item(language=language, key=key)
        if item and item.get("value"):
            return str(item["value"])
        if language != "en":
            en_item = self._get_item(language="en", key=key)
            if en_item and en_item.get("value"):
                logger.warning(
                    "translation.fallback key=%s requested_language=%s fallback_language=en",
                    key,
                    language,
                )
                return str(en_item["value"])
        if fallback is not None:
            return fallback
        logger.warning("translation.missing_all key=%s requested_language=%s", key, language)
        return key

    def translate_batch(self, *, keys: List[str], language: str) -> Dict[str, str]:
        """Translate several keys at once. Returns key -> resolved value."""
        if not keys:
            return {}
        primary = self._bulk_fetch(language=language, keys=keys)
        result: Dict[str, str] = {}
        missing: List[str] = []
        for k in keys:
            val = primary.get(k)
            if val:
                result[k] = val
            else:
                missing.append(k)
        if missing and language != "en":
            en_map = self._bulk_fetch(language="en", keys=missing)
            for k in missing:
                result[k] = en_map.get(k, k)
        else:
            for k in missing:
                result[k] = k
        return result

    def _bulk_fetch(self, *, language: str, keys: List[str]) -> Dict[str, str]:
        """Fetch values for multiple keys in one language using BatchGetItem.

        Chunks requests at 100 keys per call (DynamoDB's hard limit) and
        re-queues any ``UnprocessedKeys`` (returned under heavy throttling) so
        no key is silently dropped.  Falls back to individual ``GetItem`` for a
        chunk only if ``BatchGetItem`` raises (e.g. the table is absent in a
        minimal test environment), preserving correctness.

        ``BatchGetItem`` is supported identically by DynamoDB Local / moto (dev,
        tests) and AWS DynamoDB (prod), so there is no mock-specific path
        (SECOPS-007 dev/prod parity).
        """
        if not keys:
            return {}

        # De-duplicate while preserving order; BatchGetItem rejects dupe keys.
        seen: set = set()
        pending: List[str] = []
        for k in keys:
            if k not in seen:
                seen.add(k)
                pending.append(k)

        table = T.kyc_translations
        table_name = table.name
        client = table.meta.client
        out: Dict[str, str] = {}

        while pending:
            chunk, pending = pending[:_BATCH_GET_CHUNK], pending[_BATCH_GET_CHUNK:]
            request_items = {
                table_name: {
                    "Keys": [{"language_code": language, "key": k} for k in chunk],
                }
            }
            try:
                resp = client.batch_get_item(RequestItems=request_items)
            except Exception:
                logger.exception(
                    "kyc_translations._bulk_fetch batch_get_item failed "
                    "language=%s keys_count=%d (falling back to GetItem)",
                    language,
                    len(chunk),
                )
                # Fall back to individual GetItem for this chunk on failure.
                for k in chunk:
                    item = self._get_item(language=language, key=k)
                    if item and item.get("value"):
                        out[k] = str(item["value"])
                continue

            for item in resp.get("Responses", {}).get(table_name, []):
                if item.get("value"):
                    out[str(item["key"])] = str(item["value"])

            # Re-queue any unprocessed keys (rare; occurs under heavy throttling).
            unprocessed = (
                resp.get("UnprocessedKeys", {}).get(table_name, {}).get("Keys", [])
            )
            if unprocessed:
                logger.warning(
                    "kyc_translations._bulk_fetch unprocessed_keys count=%d language=%s",
                    len(unprocessed),
                    language,
                )
                pending = [k["key"] for k in unprocessed] + pending

        return out

    def _query_language(
        self, *, language: str, prefix: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query all translation items for a language (optionally key-prefixed)."""
        items: List[Dict[str, Any]] = []
        kwargs: Dict[str, Any] = {}
        if prefix:
            kwargs["KeyConditionExpression"] = Key("language_code").eq(language) & Key("key").begins_with(prefix)
        else:
            kwargs["KeyConditionExpression"] = Key("language_code").eq(language) & Key("key").begins_with(_KEY_PREFIX)
        try:
            resp = T.kyc_translations.query(**kwargs)
            items.extend(resp.get("Items", []))
            while resp.get("LastEvaluatedKey"):
                resp = T.kyc_translations.query(ExclusiveStartKey=resp["LastEvaluatedKey"], **kwargs)
                items.extend(resp.get("Items", []))
        except Exception:
            logger.exception("kyc_translations query failed for language=%s", language)
        return items

    # ── bundle for a locale (user-facing) ────────────────────────────

    def get_bundle(
        self, *, language: str, prefix: Optional[str] = None, published_only: bool = True
    ) -> Dict[str, str]:
        """Return a key -> value map for a locale, with English fallback merged in.

        English keys provide the baseline; locale-specific values override them.
        """
        en_items = self._query_language(language="en", prefix=prefix)
        merged: Dict[str, str] = {}
        for it in en_items:
            if published_only and it.get("status") not in (None, "published"):
                continue
            if it.get("value"):
                merged[it["key"]] = str(it["value"])
        if language != "en":
            loc_items = self._query_language(language=language, prefix=prefix)
            for it in loc_items:
                if published_only and it.get("status") not in (None, "published"):
                    continue
                if it.get("value"):
                    merged[it["key"]] = str(it["value"])
        return merged

    # ── admin CRUD ───────────────────────────────────────────────────

    def set_translation(
        self,
        *,
        key: str,
        language: str,
        value: str,
        context: str = "",
        status: str = "published",
        admin_sub: str,
    ) -> Dict[str, Any]:
        """Create or update a translation string (last-write-wins)."""
        if status not in _VALID_STATUSES:
            status = "published"
        item = {
            "language_code": language,
            "key": key,
            "value": value,
            "context": context or "",
            "status": status,
            "updated_by": admin_sub,
            "updated_at": now_ts(),
        }
        T.kyc_translations.put_item(Item=item)
        logger.info(
            "translation.admin_edit admin_sub=%s language=%s key=%s action=upsert",
            admin_sub,
            language,
            key,
        )
        return item

    def delete_translation(self, *, key: str, language: str, admin_sub: str = "") -> None:
        T.kyc_translations.delete_item(Key={"language_code": language, "key": key})
        logger.info(
            "translation.admin_edit admin_sub=%s language=%s key=%s action=delete",
            admin_sub,
            language,
            key,
        )

    def list_translations(
        self,
        *,
        language: str,
        prefix: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        items = self._query_language(language=language, prefix=prefix)
        if status:
            items = [it for it in items if it.get("status") == status]
        items.sort(key=lambda it: it.get("key", ""))
        return items[: max(1, min(limit, 500))]

    def bulk_import(
        self,
        *,
        language: str,
        translations: Dict[str, str],
        status: str = "draft",
        admin_sub: str,
    ) -> Dict[str, Any]:
        if status not in _VALID_STATUSES:
            status = "draft"
        imported = 0
        skipped = 0
        errors: List[str] = []
        for key, value in translations.items():
            if not value or not str(value).strip():
                skipped += 1
                continue
            if len(str(value)) > 10000:
                errors.append(f"{key}: value too long")
                skipped += 1
                continue
            try:
                self.set_translation(
                    key=key,
                    language=language,
                    value=str(value),
                    status=status,
                    admin_sub=admin_sub,
                )
                imported += 1
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(f"{key}: {exc}")
                skipped += 1
        logger.info(
            "translation.bulk_import admin_sub=%s language=%s imported_count=%d error_count=%d",
            admin_sub,
            language,
            imported,
            len(errors),
        )
        return {"imported": imported, "skipped": skipped, "errors": errors}

    def export_language(self, *, language: str) -> Dict[str, str]:
        items = self._query_language(language=language)
        return {it["key"]: str(it.get("value", "")) for it in items if it.get("value")}

    # ── coverage reporting ───────────────────────────────────────────

    def get_translation_coverage(self, *, language: str) -> Dict[str, Any]:
        en_keys = {it["key"] for it in self._query_language(language="en")}
        total = len(en_keys)
        if language == "en":
            translated = total
            missing = 0
        else:
            loc_keys = {it["key"] for it in self._query_language(language=language) if it.get("value")}
            translated = len(en_keys & loc_keys)
            missing = total - translated
        pct = round(translated / total, 3) if total else 0.0
        return {
            "language_code": language,
            "total_keys": total,
            "translated_keys": translated,
            "missing_keys": missing,
            "coverage_pct": pct,
        }

    def coverage_report(self) -> Dict[str, Any]:
        languages: Dict[str, Any] = {}
        for code in self.supported_locales():
            languages[code] = self.get_translation_coverage(language=code)
        return {"languages": languages}

    # ── localization of KYC surfaces ─────────────────────────────────

    def localize_questionnaire(
        self, *, questionnaire: Dict[str, Any], language: str
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Translate a questionnaire dict (title/description/questions[].label/hint).

        Returns (localized_questionnaire, fallback_keys). Keys that resolved to
        their literal key (no translation in any language) are reported as
        fallbacks.
        """
        q = dict(questionnaire or {})
        slug = q.get("slug") or q.get("published_slug") or q.get("questionnaire_id") or ""
        fallback_keys: List[str] = []

        def _apply(field_key: str, current: Any) -> Any:
            resolved = self.translate(key=field_key, language=language, fallback=current if isinstance(current, str) else "")
            if resolved == field_key:
                fallback_keys.append(field_key)
                return current
            return resolved

        if slug:
            q["title"] = _apply(f"kyc.questionnaire.title.{slug}", q.get("title", ""))
            q["description"] = _apply(
                f"kyc.questionnaire.description.{slug}", q.get("description", "")
            )

        questions = q.get("questions")
        if isinstance(questions, list):
            new_questions = []
            for question in questions:
                if not isinstance(question, dict):
                    new_questions.append(question)
                    continue
                qd = dict(question)
                qid = qd.get("question_id") or qd.get("id")
                if qid:
                    qd["label"] = _apply(f"kyc.question.label.{qid}", qd.get("label", ""))
                    if qd.get("hint") is not None:
                        qd["hint"] = _apply(f"kyc.question.hint.{qid}", qd.get("hint", ""))
                new_questions.append(qd)
            q["questions"] = new_questions

        return q, fallback_keys

    def localize_legal_notice(self, *, version: str, language: str) -> Tuple[str, bool]:
        """Return (text, is_fallback) for a signature legal notice in a locale."""
        key = f"kyc.legal_notice.{version}"
        item = self._get_item(language=language, key=key)
        if item and item.get("value"):
            return str(item["value"]), False
        if language != "en":
            en_item = self._get_item(language="en", key=key)
            if en_item and en_item.get("value"):
                return str(en_item["value"]), True
        # No stored notice — return empty with fallback flag.
        return "", True

    def localize_email(
        self, *, event: str, language: str, variables: Optional[Dict[str, str]] = None
    ) -> Tuple[str, str]:
        """Return (subject, body) for a KYC notification email in a locale.

        ``{{var}}`` placeholders in the translated templates are substituted.
        """
        variables = variables or {}
        subject = self.translate(
            key=f"kyc.email.subject.{event}", language=language, fallback=event
        )
        body = self.translate(
            key=f"kyc.email.body.{event}", language=language, fallback=""
        )
        return _substitute(subject, variables), _substitute(body, variables)


_PLACEHOLDER_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def _substitute(template: str, variables: Dict[str, str]) -> str:
    def _repl(m: "re.Match[str]") -> str:
        name = m.group(1)
        return str(variables.get(name, m.group(0)))

    return _PLACEHOLDER_RE.sub(_repl, template or "")


# Module-level singleton (mirrors other KYC service patterns).
kyc_translation_service = KycTranslationService()
