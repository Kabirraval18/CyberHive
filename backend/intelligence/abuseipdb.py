from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from flask import current_app

from backend.extensions import db
from backend.models import IPIntelligence

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
PROVIDER_NAME = "abuseipdb"


class AbuseIPDBError(RuntimeError):
    def __init__(self, message: str, *, status: str) -> None:
        super().__init__(message)
        self.status = status


def _now_utc_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def validate_public_ip(ip_address: str) -> ipaddress._BaseAddress:
    try:
        parsed = ipaddress.ip_address(ip_address.strip())
    except ValueError as exc:
        raise AbuseIPDBError(
            "Invalid IP address.",
            status="invalid_ip",
        ) from exc

    if not parsed.is_global:
        raise AbuseIPDBError(
            "IP address is not globally routable and will not be queried.",
            status="non_public_ip",
        )

    return parsed


def _cached_record(ip_address: str) -> IPIntelligence | None:
    now = _now_utc_naive()
    record = (
        IPIntelligence.query
        .filter_by(
            ip_address=ip_address,
            provider=PROVIDER_NAME,
        )
        .one_or_none()
    )
    if record is None:
        return None
    if record.expires_at is not None and record.expires_at > now:
        return record
    return None


def _serialize_record(record: IPIntelligence) -> dict[str, Any]:
    return {
        "provider": record.provider,
        "ip_address": record.ip_address,
        "reputation": record.reputation,
        "abuse_confidence": record.abuse_confidence,
        "report_count": record.report_count,
        "country": record.country,
        "asn": record.asn,
        "isp": record.isp,
        "category_data": record.category_data,
        "provider_metadata": record.provider_metadata,
        "retrieved_at": record.retrieved_at.isoformat() if record.retrieved_at else None,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
    }


def _parse_provider_response(payload: Any, ip_address: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise AbuseIPDBError(
            "Provider returned a malformed JSON object.",
            status="malformed_response",
        )

    data = payload.get("data")
    if not isinstance(data, dict):
        raise AbuseIPDBError(
            "Provider response does not contain a data object.",
            status="malformed_response",
        )

    response_ip = data.get("ipAddress")
    if response_ip and response_ip != ip_address:
        raise AbuseIPDBError(
            "Provider response IP does not match the requested address.",
            status="unexpected_response",
        )

    abuse_confidence = data.get("abuseConfidenceScore")
    total_reports = data.get("totalReports")

    if abuse_confidence is not None:
        try:
            abuse_confidence = max(0, min(100, int(abuse_confidence)))
        except (TypeError, ValueError) as exc:
            raise AbuseIPDBError(
                "Provider returned an invalid abuse confidence score.",
                status="malformed_response",
            ) from exc

    if total_reports is not None:
        try:
            total_reports = max(0, int(total_reports))
        except (TypeError, ValueError) as exc:
            raise AbuseIPDBError(
                "Provider returned an invalid report count.",
                status="malformed_response",
            ) from exc

    country = data.get("countryName") or data.get("countryCode")
    asn = data.get("asn")
    if asn is not None:
        asn = str(asn)

    provider_metadata = {
        "usage_type": data.get("usageType"),
        "domain": data.get("domain"),
        "hostnames": data.get("hostnames"),
        "is_whitelisted": data.get("isWhitelisted"),
        "ip_version": data.get("ipVersion"),
        "is_public": data.get("isPublic"),
    }

    return {
        "abuse_confidence": abuse_confidence,
        "report_count": total_reports,
        "country": country,
        "asn": asn,
        "isp": data.get("isp"),
        "category_data": data.get("reports") if isinstance(data.get("reports"), list) else None,
        "provider_metadata": provider_metadata,
    }


def lookup_abuseipdb(
    ip_address: str,
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    try:
        parsed = validate_public_ip(ip_address)
    except AbuseIPDBError as exc:
        return {
            "success": False,
            "status": exc.status,
            "error": str(exc),
        }

    normalized_ip = str(parsed)
    config = current_app.config

    if not config.get("ABUSEIPDB_ENABLED", True):
        return {
            "success": False,
            "status": "disabled",
            "error": "AbuseIPDB integration is disabled.",
        }

    api_key = str(config.get("ABUSEIPDB_API_KEY") or "").strip()
    if not api_key:
        return {
            "success": False,
            "status": "not_configured",
            "error": "AbuseIPDB API key is not configured.",
        }

    if not force_refresh:
        cached = _cached_record(normalized_ip)
        if cached is not None:
            return {
                "success": True,
                "status": "cached",
                "data": _serialize_record(cached),
            }

    max_age_days = int(config.get("ABUSEIPDB_MAX_AGE_DAYS", 90))
    max_age_days = max(1, min(365, max_age_days))

    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            headers={
                "Accept": "application/json",
                "Key": api_key,
            },
            params={
                "ipAddress": normalized_ip,
                "maxAgeInDays": max_age_days,
            },
            timeout=(3, 10),
        )
    except requests.Timeout as exc:
        return {
            "success": False,
            "status": "timeout",
            "error": "AbuseIPDB request timed out.",
        }
    except requests.RequestException as exc:
        return {
            "success": False,
            "status": "provider_unavailable",
            "error": "AbuseIPDB provider request failed.",
        }

    if response.status_code == 429:
        return {
            "success": False,
            "status": "rate_limited",
            "error": "AbuseIPDB rate limit was reached.",
        }

    if response.status_code in {401, 403}:
        return {
            "success": False,
            "status": "authentication_error",
            "error": "AbuseIPDB rejected the configured credentials.",
        }

    if response.status_code >= 400:
        return {
            "success": False,
            "status": "provider_error",
            "error": f"AbuseIPDB returned HTTP {response.status_code}.",
        }

    try:
        payload = response.json()
    except ValueError as exc:
        return {
            "success": False,
            "status": "malformed_response",
            "error": "AbuseIPDB did not return valid JSON.",
        }

    try:
        normalized = _parse_provider_response(payload, normalized_ip)
    except AbuseIPDBError as exc:
        return {
            "success": False,
            "status": exc.status,
            "error": str(exc),
        }

    retrieved_at = _now_utc_naive()
    expires_at = retrieved_at + timedelta(
        seconds=int(config.get("INTEL_CACHE_SECONDS", 86400))
    )

    record = (
        IPIntelligence.query
        .filter_by(
            ip_address=normalized_ip,
            provider=PROVIDER_NAME,
        )
        .one_or_none()
    )

    if record is None:
        record = IPIntelligence(
            ip_address=normalized_ip,
            provider=PROVIDER_NAME,
        )
        db.session.add(record)

    record.reputation = None
    record.abuse_confidence = normalized["abuse_confidence"]
    record.report_count = normalized["report_count"]
    record.country = normalized["country"]
    record.asn = normalized["asn"]
    record.isp = normalized["isp"]
    record.category_data = normalized["category_data"]
    record.provider_metadata = normalized["provider_metadata"]
    record.retrieved_at = retrieved_at
    record.expires_at = expires_at

    db.session.commit()

    return {
        "success": True,
        "status": "success",
        "data": _serialize_record(record),
    }
