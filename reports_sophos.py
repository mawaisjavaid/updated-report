#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Athena Sophos Central Report
----------------------------
Builds daily, weekly, monthly, or custom Sophos Central reports from:
  - athena-sophos-alerts*
  - athena-sophos-audit*
  - athena-sophos-endpoints*
  - athena-sophos-outbreaks*

The report includes:
  - Sophos alert/event severity and activity trends
  - Endpoint health, enrollment, isolation, threat, and last-seen posture
  - Administrative/response audit activity
  - Outbreak correlation activity
  - Athena-AI insights with rule-based fallback
  - Sophos-specific security and operational recommendations

Usage:
  python3 reports_sophos.py daily
  python3 reports_sophos.py weekly
  python3 reports_sophos.py monthly
  python3 reports_sophos.py custom 2026-06-01T00:00:00Z 2026-06-21T23:59:59Z

Useful test mode:
  REPORT_SOPHOS_SEND_EMAIL=false REPORT_SOPHOS_SAVE_OUTPUT=true \
    python3 reports_sophos.py daily
"""

import os
import sys
import time
import json
import html
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr
from dotenv import load_dotenv

load_dotenv()

# === GENERAL CONFIGURATION ===
ATHENA_NAME = os.getenv("ATHENA_NAME", "Athena SOC")
TENANT_NAME = os.getenv("TENANT_NAME", "test.athenasecuritygrp.com")
ATHENA_WEBSITE = os.getenv("ATHENA_WEBSITE", "https://athenasoftwaregroup.ai/")
ATHENA_DOCS = os.getenv("ATHENA_DOCS", "https://athenasoftwaregroup.ai/")
ATHENA_SUPPORT = os.getenv("ATHENA_SUPPORT", "alerts@athena.athenasecuritygrp.com")
DASHBOARD_BASE_URL = os.getenv("DASHBOARD_BASE_URL", "https://test.athenasecuritygrp.com")

# === SMTP CONFIGURATION ===
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "alerts@athenasoftwaregrp.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "alerts@athena.athenasecuritygrp.com")
SMTP_RECIPIENT = [
    item.strip()
    for item in os.getenv("SMTP_RECIPIENT", "mohammad@athenasecuritygrp.com").split(",")
    if item.strip()
]

REPORT_SOPHOS_ENABLED = os.getenv("REPORT_SOPHOS_ENABLED", "true").lower() == "true"
REPORT_SOPHOS_SEND_EMAIL = os.getenv("REPORT_SOPHOS_SEND_EMAIL", "true").lower() == "true"
REPORT_SOPHOS_SAVE_OUTPUT = os.getenv("REPORT_SOPHOS_SAVE_OUTPUT", "false").lower() == "true"
SOPHOS_ENDPOINT_STALE_DAYS = int(os.getenv("SOPHOS_ENDPOINT_STALE_DAYS", "7"))
MAX_DETAIL_ROWS = int(os.getenv("SOPHOS_MAX_DETAIL_ROWS", "10"))

# === ATHENA-AI / LLM CONFIGURATION ===
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://router.huggingface.co/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V3.1-Terminus")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"
HF_ORG_NAME = os.getenv("HF_ORG_NAME", "").strip()
LLM_CHAT_URL = f"{LLM_BASE_URL}/chat/completions"

# === OPENSEARCH CONFIGURATION ===
ES_HOST = os.getenv("ES_HOST", "https://localhost:9200").rstrip("/")
ES_USERNAME = os.getenv("ES_USERNAME", "admin")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"
ES_QUERY_TIMEOUT = int(os.getenv("ES_QUERY_TIMEOUT", "60"))

ES_INDEX_ALERTS = os.getenv("ES_INDEX_PATTERN_SOPHOS_ALERTS", "athena-sophos-alerts*")
ES_INDEX_AUDIT = os.getenv("ES_INDEX_PATTERN_SOPHOS_AUDIT", "athena-sophos-audit*")
ES_INDEX_ENDPOINTS = os.getenv("ES_INDEX_PATTERN_SOPHOS_ENDPOINTS", "athena-sophos-endpoints*")
ES_INDEX_OUTBREAKS = os.getenv("ES_INDEX_PATTERN_SOPHOS_OUTBREAKS", "athena-sophos-outbreaks*")

ALERT_TIME_FIELD = os.getenv("SOPHOS_ALERT_TIME_FIELD", "created_at")
AUDIT_TIME_FIELD = os.getenv("SOPHOS_AUDIT_TIME_FIELD", "timestamp")
ENDPOINT_TIME_FIELD = os.getenv("SOPHOS_ENDPOINT_TIME_FIELD", "last_seen_at")
OUTBREAK_TIME_FIELD = os.getenv("SOPHOS_OUTBREAK_TIME_FIELD", "correlated_at")

# === PATHS / LOGGING ===
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "sophos_reporting.log")
REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", os.path.join(SCRIPT_DIR, "generated_reports"))


def log(message):
    now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
    line = f"{now}: {message}\n"
    print(line, end="")
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except Exception:
        pass


def es_search(index_pattern, query):
    """Run an OpenSearch query and tolerate missing optional Sophos indices."""
    import requests
    import urllib3
    from requests.auth import HTTPBasicAuth

    if not ES_VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    url = f"{ES_HOST}/{index_pattern}/_search"
    try:
        response = requests.post(
            url,
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            json=query,
            auth=HTTPBasicAuth(ES_USERNAME, ES_PASSWORD) if ES_USERNAME or ES_PASSWORD else None,
            verify=ES_VERIFY_SSL,
            timeout=ES_QUERY_TIMEOUT,
        )
        if response.status_code != 200:
            log(
                f"OpenSearch query failed for {index_pattern}: "
                f"{response.status_code} - {response.text[:500]}"
            )
            return {}
        return response.json()
    except Exception as exc:
        log(f"OpenSearch query exception for {index_pattern}: {exc}")
        return {}


_FIELD_CAPS_CACHE = {}


def agg_field(index_pattern, field):
    """Return an aggregatable field, preferring the base field then .keyword."""
    cache_key = (index_pattern, field)
    if cache_key in _FIELD_CAPS_CACHE:
        return _FIELD_CAPS_CACHE[cache_key]

    import requests
    import urllib3
    from requests.auth import HTTPBasicAuth

    if not ES_VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    candidates = [field, f"{field}.keyword"]
    try:
        response = requests.get(
            f"{ES_HOST}/{index_pattern}/_field_caps",
            params={
                "fields": ",".join(candidates),
                "ignore_unavailable": "true",
                "allow_no_indices": "true",
            },
            auth=HTTPBasicAuth(ES_USERNAME, ES_PASSWORD) if ES_USERNAME or ES_PASSWORD else None,
            verify=ES_VERIFY_SSL,
            timeout=30,
        )
        if response.status_code == 200:
            fields = response.json().get("fields", {})
            for candidate in candidates:
                for metadata in fields.get(candidate, {}).values():
                    if metadata.get("aggregatable") is True:
                        _FIELD_CAPS_CACHE[cache_key] = candidate
                        return candidate
        else:
            log(
                f"Field caps check failed for {index_pattern}/{field}: "
                f"{response.status_code} - {response.text[:200]}"
            )
    except Exception as exc:
        log(f"Field caps exception for {index_pattern}/{field}: {exc}")

    # Most fields in the supplied Sophos templates are already keyword fields.
    # This fallback is primarily for text fields such as description.
    fallback = f"{field}.keyword"
    _FIELD_CAPS_CACHE[cache_key] = fallback
    return fallback


def terms_agg(index_pattern, field, size=10):
    return {"terms": {"field": agg_field(index_pattern, field), "size": size}}


def range_query(time_field, time_from, time_to):
    return {
        "range": {
            time_field: {
                "gte": time_from,
                "lte": time_to,
                "format": "strict_date_optional_time",
            }
        }
    }


def safe_buckets(aggregations, name):
    if not aggregations:
        return []
    return aggregations.get(name, {}).get("buckets", [])


def bucket_dict(aggregations, name):
    return {
        str(bucket.get("key", "Unknown")): int(bucket.get("doc_count", 0) or 0)
        for bucket in safe_buckets(aggregations, name)
    }


def metric_value(aggregations, name, default=0):
    if not aggregations:
        return default
    value = aggregations.get(name, {}).get("value", default)
    return default if value is None else value


def int_metric(aggregations, name):
    try:
        return int(metric_value(aggregations, name, 0) or 0)
    except Exception:
        return 0


def total_hits(response):
    total = response.get("hits", {}).get("total", 0) if response else 0
    if isinstance(total, dict):
        return int(total.get("value", 0) or 0)
    return int(total or 0)


def parse_hits(response):
    records = []
    for hit in response.get("hits", {}).get("hits", []) if response else []:
        source = hit.get("_source", {}) or {}
        source["_index"] = hit.get("_index", "")
        records.append(source)
    return records


def count_bucket_case_insensitive(data, accepted_values):
    accepted = {str(value).strip().lower() for value in accepted_values}
    return sum(
        int(count or 0)
        for key, count in (data or {}).items()
        if str(key).strip().lower() in accepted
    )


def count_bucket_contains(data, terms, exclude_terms=None):
    terms = [term.lower() for term in terms]
    exclude_terms = [term.lower() for term in (exclude_terms or [])]
    total = 0
    for key, count in (data or {}).items():
        normalized = str(key).strip().lower()
        if any(term in normalized for term in terms) and not any(term in normalized for term in exclude_terms):
            total += int(count or 0)
    return total


def query_alerts(time_from, time_to):
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [range_query(ALERT_TIME_FIELD, time_from, time_to)]}},
        "aggs": {
            "total_records": {"value_count": {"field": "sophos_id"}},
            "record_types": terms_agg(ES_INDEX_ALERTS, "record_type", 10),
            "severities": terms_agg(ES_INDEX_ALERTS, "severity", 10),
            "severity_scores": terms_agg(ES_INDEX_ALERTS, "severity_score", 10),
            "event_types": terms_agg(ES_INDEX_ALERTS, "event_type", 15),
            "alert_types": terms_agg(ES_INDEX_ALERTS, "alert_type", 15),
            "statuses": terms_agg(ES_INDEX_ALERTS, "status", 10),
            "acknowledged": terms_agg(ES_INDEX_ALERTS, "acknowledged", 5),
            "xdr": terms_agg(ES_INDEX_ALERTS, "xdr", 5),
            "xdr_elevated": terms_agg(ES_INDEX_ALERTS, "xdr_elevated", 5),
            "top_endpoints": terms_agg(ES_INDEX_ALERTS, "endpoint_name", 10),
            "top_sources": terms_agg(ES_INDEX_ALERTS, "source", 10),
            "top_descriptions": terms_agg(ES_INDEX_ALERTS, "description", 10),
            "high_or_critical": {"filter": {"range": {"severity_score": {"gte": 3}}}},
            "critical": {
                "filter": {
                    "bool": {
                        "should": [
                            {"term": {"severity": "critical"}},
                            {"range": {"severity_score": {"gte": 4}}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "unacknowledged": {"filter": {"term": {"acknowledged": False}}},
            "xdr_elevated_count": {"filter": {"term": {"xdr_elevated": True}}},
        },
    }
    return es_search(ES_INDEX_ALERTS, query)


def query_recent_alerts(time_from, time_to, size=None):
    size = size or MAX_DETAIL_ROWS
    query = {
        "size": size,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [range_query(ALERT_TIME_FIELD, time_from, time_to)],
                "should": [
                    {"range": {"severity_score": {"gte": 3}}},
                    {"term": {"record_type": "alert"}},
                ],
                "minimum_should_match": 1,
            }
        },
        "sort": [
            {"severity_score": {"order": "desc", "unmapped_type": "integer"}},
            {ALERT_TIME_FIELD: {"order": "desc", "unmapped_type": "date"}},
        ],
        "_source": [
            "sophos_id",
            "tenant_name",
            "record_type",
            "event_type",
            "alert_type",
            "severity",
            "severity_score",
            "status",
            "acknowledged",
            "description",
            "endpoint_id",
            "endpoint_name",
            "xdr",
            "xdr_elevated",
            "source",
            "created_at",
        ],
    }
    return es_search(ES_INDEX_ALERTS, query)


def query_endpoints(time_to):
    stale_before = (
        datetime.fromisoformat(time_to.replace("Z", "+00:00"))
        - timedelta(days=SOPHOS_ENDPOINT_STALE_DAYS)
    ).isoformat().replace("+00:00", "Z")

    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {"match_all": {}},
        "aggs": {
            "total_endpoints": {"value_count": {"field": "sophos_id"}},
            "health_status": terms_agg(ES_INDEX_ENDPOINTS, "health_status", 20),
            "isolation_status": terms_agg(ES_INDEX_ENDPOINTS, "isolation_status", 20),
            "os_family": terms_agg(ES_INDEX_ENDPOINTS, "os_family", 10),
            "operating_systems": terms_agg(ES_INDEX_ENDPOINTS, "os", 15),
            "enrolled": terms_agg(ES_INDEX_ENDPOINTS, "enrolled", 5),
            "tenants": terms_agg(ES_INDEX_ENDPOINTS, "tenant_name", 10),
            "threat_count_total": {"sum": {"field": "threat_count"}},
            "threat_count_max": {"max": {"field": "threat_count"}},
            "endpoints_with_threats": {"filter": {"range": {"threat_count": {"gt": 0}}}},
            "seen_in_period": {
                "filter": {
                    "range": {
                        ENDPOINT_TIME_FIELD: {
                            "gte": stale_before,
                            "lte": time_to,
                            "format": "strict_date_optional_time",
                        }
                    }
                }
            },
            "stale_endpoints": {
                "filter": {
                    "bool": {
                        "should": [
                            {
                                "range": {
                                    ENDPOINT_TIME_FIELD: {
                                        "lt": stale_before,
                                        "format": "strict_date_optional_time",
                                    }
                                }
                            },
                            {"bool": {"must_not": {"exists": {"field": ENDPOINT_TIME_FIELD}}}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
        },
    }
    return es_search(ES_INDEX_ENDPOINTS, query)


def query_endpoint_details(time_to, size=None):
    size = size or MAX_DETAIL_ROWS
    stale_before = (
        datetime.fromisoformat(time_to.replace("Z", "+00:00"))
        - timedelta(days=SOPHOS_ENDPOINT_STALE_DAYS)
    ).isoformat().replace("+00:00", "Z")

    query = {
        "size": size,
        "track_total_hits": True,
        "query": {
            "bool": {
                "should": [
                    {"range": {"threat_count": {"gt": 0}}},
                    {"range": {ENDPOINT_TIME_FIELD: {"lt": stale_before}}},
                    {"term": {"enrolled": False}},
                    {"terms": {"health_status": ["bad", "red", "suspicious", "warning", "degraded", "unhealthy", "critical"]}},
                ],
                "minimum_should_match": 1,
            }
        },
        "sort": [
            {"threat_count": {"order": "desc", "unmapped_type": "integer"}},
            {ENDPOINT_TIME_FIELD: {"order": "asc", "unmapped_type": "date", "missing": "_first"}},
        ],
        "_source": [
            "sophos_id",
            "tenant_name",
            "hostname",
            "os",
            "os_family",
            "health_status",
            "isolation_status",
            "last_seen_at",
            "ip_addresses",
            "threat_count",
            "enrolled",
            "synced_at",
        ],
    }
    return es_search(ES_INDEX_ENDPOINTS, query)


def query_audit(time_from, time_to):
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [range_query(AUDIT_TIME_FIELD, time_from, time_to)]}},
        "aggs": {
            "total_actions": {"value_count": {"field": "audit_id"}},
            "actions": terms_agg(ES_INDEX_AUDIT, "action", 15),
            "performed_by": terms_agg(ES_INDEX_AUDIT, "performed_by", 10),
            "roles": terms_agg(ES_INDEX_AUDIT, "role", 10),
            "statuses": terms_agg(ES_INDEX_AUDIT, "status", 10),
            "source_ips": terms_agg(ES_INDEX_AUDIT, "source_ip", 10),
            "tenants": terms_agg(ES_INDEX_AUDIT, "tenant_name", 10),
            "endpoint_actions": {"filter": {"exists": {"field": "endpoint_id"}}},
            "alert_actions": {"filter": {"exists": {"field": "alert_id"}}},
            "command_actions": {"filter": {"exists": {"field": "command_id"}}},
        },
    }
    return es_search(ES_INDEX_AUDIT, query)


def query_recent_audit(time_from, time_to, size=None):
    size = size or MAX_DETAIL_ROWS
    query = {
        "size": size,
        "track_total_hits": True,
        "query": {"bool": {"filter": [range_query(AUDIT_TIME_FIELD, time_from, time_to)]}},
        "sort": [{AUDIT_TIME_FIELD: {"order": "desc", "unmapped_type": "date"}}],
        "_source": [
            "audit_id",
            "tenant_name",
            "action",
            "performed_by",
            "role",
            "status",
            "message",
            "endpoint_id",
            "alert_id",
            "command_id",
            "timestamp",
            "source_ip",
        ],
    }
    return es_search(ES_INDEX_AUDIT, query)


def query_outbreaks(time_from, time_to):
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": [range_query(OUTBREAK_TIME_FIELD, time_from, time_to)]}},
        "aggs": {
            "total_outbreaks": {"value_count": {"field": "outbreak_id"}},
            "total_threats": {"sum": {"field": "threat_count"}},
            "max_threats": {"max": {"field": "threat_count"}},
            "average_threats": {"avg": {"field": "threat_count"}},
            "tenants": terms_agg(ES_INDEX_OUTBREAKS, "tenant_name", 10),
        },
    }
    return es_search(ES_INDEX_OUTBREAKS, query)


def query_recent_outbreaks(time_from, time_to, size=None):
    size = size or MAX_DETAIL_ROWS
    query = {
        "size": size,
        "track_total_hits": True,
        "query": {"bool": {"filter": [range_query(OUTBREAK_TIME_FIELD, time_from, time_to)]}},
        "sort": [
            {"threat_count": {"order": "desc", "unmapped_type": "integer"}},
            {OUTBREAK_TIME_FIELD: {"order": "desc", "unmapped_type": "date"}},
        ],
        "_source": [
            "outbreak_id",
            "tenant_name",
            "threat_count",
            "window_start",
            "window_end",
            "correlated_at",
            "alert_ids",
        ],
    }
    return es_search(ES_INDEX_OUTBREAKS, query)


def calculate_previous_period(time_from, time_to):
    current_from = datetime.fromisoformat(time_from.replace("Z", "+00:00"))
    current_to = datetime.fromisoformat(time_to.replace("Z", "+00:00"))
    duration = current_to - current_from
    previous_from = current_from - duration
    previous_to = current_from - timedelta(microseconds=1)
    return (
        previous_from.isoformat().replace("+00:00", "Z"),
        previous_to.isoformat().replace("+00:00", "Z"),
    )


def pct_change(current, previous):
    if previous == 0:
        if current:
            return 100.0, "increase"
        return 0.0, "no change"
    change = ((current - previous) / previous) * 100.0
    if change > 0:
        return abs(change), "increase"
    if change < 0:
        return abs(change), "decrease"
    return 0.0, "no change"


def collect_stats(time_from, time_to, include_endpoint_details=True):
    alert_response = query_alerts(time_from, time_to)
    audit_response = query_audit(time_from, time_to)
    outbreak_response = query_outbreaks(time_from, time_to)
    endpoint_response = query_endpoints(time_to)

    alert_aggs = alert_response.get("aggregations", {})
    audit_aggs = audit_response.get("aggregations", {})
    outbreak_aggs = outbreak_response.get("aggregations", {})
    endpoint_aggs = endpoint_response.get("aggregations", {})

    severity = bucket_dict(alert_aggs, "severities")
    record_types = bucket_dict(alert_aggs, "record_types")
    health_status = bucket_dict(endpoint_aggs, "health_status")
    isolation_status = bucket_dict(endpoint_aggs, "isolation_status")
    enrolled = bucket_dict(endpoint_aggs, "enrolled")
    audit_statuses = bucket_dict(audit_aggs, "statuses")
    alert_statuses = bucket_dict(alert_aggs, "statuses")

    critical_count = count_bucket_case_insensitive(severity, {"critical"})
    high_count = count_bucket_case_insensitive(severity, {"high"})
    medium_count = count_bucket_case_insensitive(severity, {"medium"})
    low_count = count_bucket_case_insensitive(severity, {"low", "informational", "info"})

    explicit_at_risk = {
        "bad", "red", "suspicious", "warning", "yellow", "degraded",
        "unhealthy", "critical", "malware", "threat", "at risk", "at-risk",
    }
    healthy_values = {"good", "green", "healthy", "protected", "normal", "ok"}
    unknown_values = {"unknown", "n/a", "none", "not available", ""}

    at_risk_endpoints = count_bucket_case_insensitive(health_status, explicit_at_risk)
    healthy_endpoints = count_bucket_case_insensitive(health_status, healthy_values)
    unknown_health = count_bucket_case_insensitive(health_status, unknown_values)
    isolated_endpoints = count_bucket_contains(
        isolation_status,
        ["isolated"],
        ["not isolated", "not_isolated", "unisolate", "notisolated"],
    )
    unenrolled_endpoints = count_bucket_case_insensitive(enrolled, {"false", "0", "no"})
    failed_audits = count_bucket_case_insensitive(
        audit_statuses,
        {"failed", "failure", "error", "denied", "unauthorized", "rejected"},
    )
    active_alerts = count_bucket_case_insensitive(
        alert_statuses,
        {"active", "open", "new", "unresolved", "in progress", "in_progress"},
    )

    recent_alerts = parse_hits(query_recent_alerts(time_from, time_to))
    recent_audit = parse_hits(query_recent_audit(time_from, time_to))
    recent_outbreaks = parse_hits(query_recent_outbreaks(time_from, time_to))
    endpoint_details = parse_hits(query_endpoint_details(time_to)) if include_endpoint_details else []

    total_records = int_metric(alert_aggs, "total_records") or total_hits(alert_response)
    total_endpoints = int_metric(endpoint_aggs, "total_endpoints") or total_hits(endpoint_response)
    total_audit = int_metric(audit_aggs, "total_actions") or total_hits(audit_response)
    total_outbreaks = int_metric(outbreak_aggs, "total_outbreaks") or total_hits(outbreak_response)

    stats = {
        "alerts": {
            "total": total_records,
            "record_types": record_types,
            "severities": severity,
            "severity_scores": bucket_dict(alert_aggs, "severity_scores"),
            "event_types": bucket_dict(alert_aggs, "event_types"),
            "alert_types": bucket_dict(alert_aggs, "alert_types"),
            "statuses": alert_statuses,
            "acknowledged": bucket_dict(alert_aggs, "acknowledged"),
            "xdr": bucket_dict(alert_aggs, "xdr"),
            "xdr_elevated": bucket_dict(alert_aggs, "xdr_elevated"),
            "top_endpoints": bucket_dict(alert_aggs, "top_endpoints"),
            "top_sources": bucket_dict(alert_aggs, "top_sources"),
            "top_descriptions": bucket_dict(alert_aggs, "top_descriptions"),
            "high_or_critical": int(alert_aggs.get("high_or_critical", {}).get("doc_count", 0) or 0),
            "critical": max(
                critical_count,
                int(alert_aggs.get("critical", {}).get("doc_count", 0) or 0),
            ),
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "unacknowledged": int(alert_aggs.get("unacknowledged", {}).get("doc_count", 0) or 0),
            "xdr_elevated_count": int(alert_aggs.get("xdr_elevated_count", {}).get("doc_count", 0) or 0),
            "active": active_alerts,
            "recent": recent_alerts,
        },
        "endpoints": {
            "total": total_endpoints,
            "health_status": health_status,
            "isolation_status": isolation_status,
            "os_family": bucket_dict(endpoint_aggs, "os_family"),
            "operating_systems": bucket_dict(endpoint_aggs, "operating_systems"),
            "enrolled": enrolled,
            "tenants": bucket_dict(endpoint_aggs, "tenants"),
            "threat_count_total": int(metric_value(endpoint_aggs, "threat_count_total", 0) or 0),
            "threat_count_max": int(metric_value(endpoint_aggs, "threat_count_max", 0) or 0),
            "with_threats": int(endpoint_aggs.get("endpoints_with_threats", {}).get("doc_count", 0) or 0),
            "recently_seen": int(endpoint_aggs.get("seen_in_period", {}).get("doc_count", 0) or 0),
            "stale": int(endpoint_aggs.get("stale_endpoints", {}).get("doc_count", 0) or 0),
            "healthy": healthy_endpoints,
            "at_risk": at_risk_endpoints,
            "unknown_health": unknown_health,
            "isolated": isolated_endpoints,
            "unenrolled": unenrolled_endpoints,
            "attention_required": endpoint_details,
        },
        "audit": {
            "total": total_audit,
            "actions": bucket_dict(audit_aggs, "actions"),
            "performed_by": bucket_dict(audit_aggs, "performed_by"),
            "roles": bucket_dict(audit_aggs, "roles"),
            "statuses": audit_statuses,
            "source_ips": bucket_dict(audit_aggs, "source_ips"),
            "tenants": bucket_dict(audit_aggs, "tenants"),
            "endpoint_actions": int(audit_aggs.get("endpoint_actions", {}).get("doc_count", 0) or 0),
            "alert_actions": int(audit_aggs.get("alert_actions", {}).get("doc_count", 0) or 0),
            "command_actions": int(audit_aggs.get("command_actions", {}).get("doc_count", 0) or 0),
            "failed": failed_audits,
            "recent": recent_audit,
        },
        "outbreaks": {
            "total": total_outbreaks,
            "threats": int(metric_value(outbreak_aggs, "total_threats", 0) or 0),
            "max_threats": int(metric_value(outbreak_aggs, "max_threats", 0) or 0),
            "average_threats": float(metric_value(outbreak_aggs, "average_threats", 0.0) or 0.0),
            "tenants": bucket_dict(outbreak_aggs, "tenants"),
            "recent": recent_outbreaks,
        },
    }

    stats["overall"] = {
        "sophos_records": stats["alerts"]["total"],
        "alert_records": count_bucket_case_insensitive(record_types, {"alert"}),
        "event_records": count_bucket_case_insensitive(record_types, {"event"}),
        "high_or_critical": stats["alerts"]["high_or_critical"],
        "critical": stats["alerts"]["critical"],
        "active_alerts": stats["alerts"]["active"],
        "total_endpoints": stats["endpoints"]["total"],
        "healthy_endpoints": stats["endpoints"]["healthy"],
        "at_risk_endpoints": stats["endpoints"]["at_risk"],
        "threatened_endpoints": stats["endpoints"]["with_threats"],
        "stale_endpoints": stats["endpoints"]["stale"],
        "audit_actions": stats["audit"]["total"],
        "failed_audits": stats["audit"]["failed"],
        "outbreaks": stats["outbreaks"]["total"],
        "outbreak_threats": stats["outbreaks"]["threats"],
    }
    return stats


def add_comparison(stats, previous_stats):
    comparable_keys = [
        "sophos_records",
        "alert_records",
        "event_records",
        "high_or_critical",
        "critical",
        "active_alerts",
        "audit_actions",
        "failed_audits",
        "outbreaks",
        "outbreak_threats",
    ]
    stats["comparisons"] = {}
    for key in comparable_keys:
        current = int(stats.get("overall", {}).get(key, 0) or 0)
        previous = int(previous_stats.get("overall", {}).get(key, 0) or 0)
        change_pct, change_type = pct_change(current, previous)
        stats["comparisons"][key] = {
            "current": current,
            "previous": previous,
            "change_pct": change_pct,
            "change_type": change_type,
        }


def fmt_num(value):
    try:
        return f"{int(value):,}"
    except Exception:
        return str(value)


def fmt_datetime(value):
    if not value:
        return "N/A"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(value)


def truncate(value, limit=100):
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def safe_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def table_rows_from_dict(data, empty="No data available", limit=10):
    if not data:
        return f"<tr><td colspan='2' style='padding:10px;color:#6b7280;'>{html.escape(empty)}</td></tr>"
    rows = []
    for key, value in sorted(data.items(), key=lambda item: item[1], reverse=True)[:limit]:
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-word;'>{html.escape(str(key))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:600;'>{fmt_num(value)}</td>"
            "</tr>"
        )
    return "".join(rows)


def card(title, value, subtitle="", color="#1e40af"):
    return f"""
    <td width="25%" style="padding:8px;vertical-align:top;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;height:120px;">
        <tr><td style="padding:16px;text-align:center;vertical-align:middle;">
          <div style="font-size:28px;font-weight:700;color:{color};">{value}</div>
          <div style="font-size:12px;text-transform:uppercase;color:#6b7280;letter-spacing:.4px;margin-top:4px;">{html.escape(title)}</div>
          <div style="font-size:11px;color:#6b7280;margin-top:6px;">{html.escape(subtitle)}</div>
        </td></tr>
      </table>
    </td>"""


def section(title, body):
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;margin:18px 0;">
      <tr><td style="padding:20px;">
        <h3 style="margin:0 0 14px 0;color:#111827;font-size:17px;border-bottom:2px solid #e5e7eb;padding-bottom:8px;">{html.escape(title)}</h3>
        {body}
      </td></tr>
    </table>"""


def build_llm_headers():
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_API_KEY}",
    }
    if HF_ORG_NAME:
        headers["X-HF-Bill-To"] = HF_ORG_NAME
    return headers


def parse_llm_json(ai_content, finish_reason=None):
    if finish_reason and finish_reason != "stop":
        log(f"LLM finish_reason={finish_reason!r}; output may be truncated or filtered")
    if not ai_content or not ai_content.strip():
        log("LLM returned empty content; using rule-based Athena-AI Insights")
        return None

    text = ai_content.strip()
    if text.startswith("```"):
        text = text[3:]
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.lstrip()
        if text.endswith("```"):
            text = text[:-3].rstrip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last > first:
        try:
            return json.loads(text[first:last + 1])
        except json.JSONDecodeError:
            pass

    log(f"Failed to parse LLM response as JSON: {ai_content[:300].replace(chr(10), ' ')!r}")
    return None


def get_ai_sophos_insights(stats, report_type, time_from, time_to):
    """Generate Athena-AI Sophos Central insights using the configured LLM."""
    if not LLM_ENABLED:
        return None
    if not LLM_API_KEY:
        log("LLM_API_KEY is not set; using rule-based Athena-AI Insights")
        return None

    try:
        import requests

        def top_items(data, limit=5):
            if not data:
                return "None"
            return "\n".join(
                f"- {key}: {value}"
                for key, value in sorted(data.items(), key=lambda item: item[1], reverse=True)[:limit]
            )

        comparison_lines = []
        for key, comparison in stats.get("comparisons", {}).items():
            comparison_lines.append(
                f"- {key}: current={comparison.get('current', 0)}, "
                f"previous={comparison.get('previous', 0)}, "
                f"change={comparison.get('change_pct', 0):.1f}% "
                f"{comparison.get('change_type', 'no change')}"
            )
        comparison_text = "\n".join(comparison_lines) or "No previous-period comparison available"

        recent_items = []
        for item in stats.get("alerts", {}).get("recent", [])[:5]:
            recent_items.append(
                f"- {item.get('created_at', 'N/A')} | severity={item.get('severity', 'unknown')} | "
                f"endpoint={item.get('endpoint_name', 'unknown')} | type={item.get('event_type') or item.get('alert_type') or 'unknown'} | "
                f"description={truncate(item.get('description', ''), 180)}"
            )
        recent_text = "\n".join(recent_items) or "None"

        prompt = f"""You are Athena-AI, a senior SOC analyst specializing in Sophos Central endpoint protection, XDR, endpoint health, alert triage, response operations, audit review, and outbreak correlation.

Generate an executive Sophos Central security insight section for a {report_type} report covering {time_from} to {time_to}.

CURRENT DATA SUMMARY:
Sophos alert/event records: {stats['overall'].get('sophos_records', 0)}
Alert records: {stats['overall'].get('alert_records', 0)}
Event records: {stats['overall'].get('event_records', 0)}
High/Critical records: {stats['overall'].get('high_or_critical', 0)}
Critical records: {stats['overall'].get('critical', 0)}
Active alerts: {stats['overall'].get('active_alerts', 0)}
Unacknowledged records: {stats['alerts'].get('unacknowledged', 0)}
XDR elevated records: {stats['alerts'].get('xdr_elevated_count', 0)}
Total endpoints: {stats['overall'].get('total_endpoints', 0)}
Healthy endpoints: {stats['overall'].get('healthy_endpoints', 0)}
Explicitly at-risk endpoints: {stats['overall'].get('at_risk_endpoints', 0)}
Endpoints with threats: {stats['overall'].get('threatened_endpoints', 0)}
Stale endpoints (>{SOPHOS_ENDPOINT_STALE_DAYS} days): {stats['overall'].get('stale_endpoints', 0)}
Isolated endpoints: {stats['endpoints'].get('isolated', 0)}
Unenrolled endpoints: {stats['endpoints'].get('unenrolled', 0)}
Audit actions: {stats['overall'].get('audit_actions', 0)}
Failed audit actions: {stats['overall'].get('failed_audits', 0)}
Outbreaks: {stats['overall'].get('outbreaks', 0)}
Threats correlated in outbreaks: {stats['overall'].get('outbreak_threats', 0)}

PERIOD COMPARISON:
{comparison_text}

SEVERITY DISTRIBUTION:
{top_items(stats.get('alerts', {}).get('severities', {}))}

TOP EVENT TYPES:
{top_items(stats.get('alerts', {}).get('event_types', {}))}

TOP ALERT TYPES:
{top_items(stats.get('alerts', {}).get('alert_types', {}))}

TOP AFFECTED ENDPOINTS:
{top_items(stats.get('alerts', {}).get('top_endpoints', {}))}

ENDPOINT HEALTH:
{top_items(stats.get('endpoints', {}).get('health_status', {}))}

ENDPOINT ISOLATION:
{top_items(stats.get('endpoints', {}).get('isolation_status', {}))}

AUDIT STATUS:
{top_items(stats.get('audit', {}).get('statuses', {}))}

RECENT IMPORTANT ALERTS/EVENTS:
{recent_text}

ANALYSIS RULES:
- Do not invent facts, malware names, root causes, remediations already performed, or containment outcomes.
- Distinguish ordinary operational events (for example successful updates) from security alerts.
- Treat high-severity macOS prerequisite/health events as protection gaps that may require checking MDM deployment, system extensions, network filters, Full Disk Access, and user-approved permissions; do not claim which prerequisite failed unless telemetry states it.
- Prioritize active/unacknowledged alerts, endpoint threat counts, explicit unhealthy states, stale endpoints, isolation state, failed response actions, and outbreaks.
- If a metric is zero or unavailable, say so clearly rather than inferring missing protection.
- Recommendations must be practical, prioritized, and tied to the supplied metrics.

Return ONLY valid JSON using this schema:
{{
  "executive_summary": "2 concise paragraphs with concrete numbers and their meaning",
  "key_findings": ["3-6 specific findings using supplied numbers"],
  "endpoint_posture": ["endpoint health, enrollment, isolation, threat, and last-seen observations"],
  "threat_observations": ["alert, severity, XDR, outbreak, and event observations"],
  "operational_observations": ["audit, update, response, or telemetry observations"],
  "recommended_actions": ["3-6 prioritized actions"],
  "overall_risk_rating": "Low/Medium/High/Critical"
}}"""

        payload = {
            "model": LLM_MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are Athena-AI, a cybersecurity analyst specializing in Sophos Central, "
                        "endpoint protection, XDR, endpoint health, incident triage, audit review, and "
                        "executive security reporting. Return only valid JSON."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
            "response_format": {"type": "json_object"},
        }

        log(f"Calling LLM at {LLM_CHAT_URL} for Athena-AI Sophos Insights...")
        response = requests.post(
            LLM_CHAT_URL,
            headers=build_llm_headers(),
            json=payload,
            timeout=(10, 180),
        )
        if response.status_code != 200:
            log(f"LLM API error: {response.status_code} - {response.text[:500]}")
            return None

        result = response.json()
        choice = result["choices"][0]
        analysis = parse_llm_json(
            choice.get("message", {}).get("content", ""),
            choice.get("finish_reason"),
        )
        if analysis:
            log("Athena-AI Sophos Insights generated successfully")
        return analysis
    except Exception as exc:
        import traceback

        log(f"Error getting Athena-AI Sophos Insights: {exc}")
        log(traceback.format_exc())
        return None


def build_rule_based_ai_insights(stats):
    """Always provide an Athena-AI section when the external LLM is unavailable."""
    overall = stats.get("overall", {})
    alerts = stats.get("alerts", {})
    endpoints = stats.get("endpoints", {})
    audit = stats.get("audit", {})
    outbreaks = stats.get("outbreaks", {})

    critical = int(overall.get("critical", 0) or 0)
    high_or_critical = int(overall.get("high_or_critical", 0) or 0)
    at_risk = int(overall.get("at_risk_endpoints", 0) or 0)
    threatened = int(overall.get("threatened_endpoints", 0) or 0)
    stale = int(overall.get("stale_endpoints", 0) or 0)
    failed_audits = int(overall.get("failed_audits", 0) or 0)
    outbreak_count = int(overall.get("outbreaks", 0) or 0)
    outbreak_threats = int(overall.get("outbreak_threats", 0) or 0)
    medium = int(alerts.get("medium", 0) or 0)

    if critical > 0 or outbreak_threats >= 25:
        risk = "Critical"
    elif high_or_critical > 0 or at_risk > 0 or outbreak_count > 0:
        risk = "High"
    elif medium > 0 or threatened > 0 or stale > 0 or failed_audits > 0:
        risk = "Medium"
    else:
        risk = "Low"

    def top_one(data):
        if not data:
            return "No dominant value available"
        key, value = sorted(data.items(), key=lambda item: item[1], reverse=True)[0]
        return f"{key} ({value:,})"

    comparisons = stats.get("comparisons", {})
    record_comparison = comparisons.get("sophos_records", {})
    comparison_sentence = (
        f"This is a {record_comparison.get('change_pct', 0):.1f}% "
        f"{record_comparison.get('change_type', 'no change')} compared with the previous equivalent period."
        if comparisons
        else "Previous-period comparison is unavailable."
    )

    endpoint_total = int(overall.get("total_endpoints", 0) or 0)
    healthy = int(overall.get("healthy_endpoints", 0) or 0)

    return {
        "overall_risk_rating": risk,
        "executive_summary": (
            f"Athena-AI analyzed {int(overall.get('sophos_records', 0) or 0):,} Sophos alert/event records, "
            f"including {high_or_critical:,} high-or-critical records and {critical:,} critical records. "
            f"{comparison_sentence} The environment currently contains {endpoint_total:,} endpoint records, "
            f"of which {healthy:,} are explicitly reported as healthy and {at_risk:,} are explicitly reported "
            f"in an at-risk state.\n\n"
            f"The selected period includes {int(overall.get('audit_actions', 0) or 0):,} audit actions and "
            f"{outbreak_count:,} outbreak records correlating {outbreak_threats:,} threats. The risk rating is "
            f"based only on the supplied Sophos telemetry; missing or zero-value metrics are not treated as proof "
            f"of either protection or compromise."
        ),
        "key_findings": [
            f"Sophos produced {int(overall.get('alert_records', 0) or 0):,} alert records and {int(overall.get('event_records', 0) or 0):,} event records.",
            f"High-or-critical activity totaled {high_or_critical:,}, including {critical:,} critical records.",
            f"Endpoint posture shows {at_risk:,} explicitly at-risk, {threatened:,} with non-zero threat counts, and {stale:,} stale endpoint records.",
            f"There were {int(alerts.get('unacknowledged', 0) or 0):,} unacknowledged records and {int(alerts.get('xdr_elevated_count', 0) or 0):,} XDR-elevated records.",
            f"Audit activity totaled {int(audit.get('total', 0) or 0):,}, with {failed_audits:,} failed/denied/error status records.",
        ],
        "endpoint_posture": [
            f"Top endpoint health state: {top_one(endpoints.get('health_status', {}))}.",
            f"Top endpoint operating-system family: {top_one(endpoints.get('os_family', {}))}.",
            f"Isolated endpoints detected from current-state fields: {int(endpoints.get('isolated', 0) or 0):,}.",
            f"Endpoints not seen within {SOPHOS_ENDPOINT_STALE_DAYS} days or missing last-seen data: {stale:,}.",
            f"Unenrolled endpoint records: {int(endpoints.get('unenrolled', 0) or 0):,}.",
        ],
        "threat_observations": [
            f"Top severity: {top_one(alerts.get('severities', {}))}.",
            f"Top event type: {top_one(alerts.get('event_types', {}))}.",
            f"Top affected endpoint: {top_one(alerts.get('top_endpoints', {}))}.",
            f"Outbreak correlation identified {outbreak_count:,} outbreak records and {outbreak_threats:,} total correlated threats.",
        ],
        "operational_observations": [
            f"Top audit action: {top_one(audit.get('actions', {}))}.",
            f"Top audit status: {top_one(audit.get('statuses', {}))}.",
            "Successful update events are treated as routine operational telemetry rather than security incidents.",
            "High-severity macOS health/prerequisite events should be validated against required MDM profiles and Sophos permissions without assuming which prerequisite failed.",
        ],
        "recommended_actions": build_sophos_recommendations(stats).get("recommendations", []),
    }


def has_event_type(stats, search_terms):
    terms = [term.lower() for term in search_terms]
    for event_type, count in stats.get("alerts", {}).get("event_types", {}).items():
        normalized = str(event_type).lower()
        if int(count or 0) > 0 and any(term in normalized for term in terms):
            return True
    return False


def build_sophos_recommendations(stats):
    """Build Sophos-specific security and operational recommendations."""
    alerts = stats.get("alerts", {})
    endpoints = stats.get("endpoints", {})
    audit = stats.get("audit", {})
    outbreaks = stats.get("outbreaks", {})

    recommendations = []
    positives = []

    critical = int(alerts.get("critical", 0) or 0)
    high_or_critical = int(alerts.get("high_or_critical", 0) or 0)
    active = int(alerts.get("active", 0) or 0)
    unacknowledged = int(alerts.get("unacknowledged", 0) or 0)
    xdr_elevated = int(alerts.get("xdr_elevated_count", 0) or 0)

    if critical > 0:
        recommendations.append(
            f"Immediately triage the {critical:,} critical Sophos records, validate affected endpoints, confirm containment status, and document remediation evidence."
        )
    elif high_or_critical > 0:
        recommendations.append(
            f"Prioritize investigation of the {high_or_critical:,} high-or-critical Sophos records and verify whether any endpoint requires containment or cleanup."
        )
    else:
        positives.append("No high-or-critical Sophos records were identified in the selected reporting period.")

    if active > 0 or unacknowledged > 0:
        recommendations.append(
            f"Review the alert queue: {active:,} records appear active/open and {unacknowledged:,} records are unacknowledged based on available status fields."
        )

    if xdr_elevated > 0:
        recommendations.append(
            f"Review the {xdr_elevated:,} XDR-elevated records and preserve investigation context, query results, and response evidence for auditability."
        )

    if has_event_type(stats, ["machealth", "mac_health", "mac health"]):
        recommendations.append(
            "Validate affected macOS devices against Sophos prerequisites: confirm the required MDM configuration profiles, system extensions, network/content filters, Full Disk Access, and user-approved permissions are present and active."
        )

    if has_event_type(stats, ["updatefailure", "updatefailed", "update failure", "update failed"]):
        recommendations.append(
            "Investigate Sophos update failures by checking endpoint connectivity, update cache/proxy settings, service health, disk space, and the endpoint update logs."
        )
    elif has_event_type(stats, ["updatesuccess", "update succeeded"]):
        positives.append("Successful Sophos endpoint update activity was observed during the selected period.")

    at_risk = int(endpoints.get("at_risk", 0) or 0)
    threatened = int(endpoints.get("with_threats", 0) or 0)
    stale = int(endpoints.get("stale", 0) or 0)
    isolated = int(endpoints.get("isolated", 0) or 0)
    unenrolled = int(endpoints.get("unenrolled", 0) or 0)
    unknown_health = int(endpoints.get("unknown_health", 0) or 0)

    if at_risk > 0 or threatened > 0:
        recommendations.append(
            f"Investigate endpoint posture exceptions: {at_risk:,} explicitly at-risk endpoint records and {threatened:,} endpoints with non-zero threat counts."
        )
    if stale > 0:
        recommendations.append(
            f"Validate connectivity and agent service health for {stale:,} endpoints not seen within {SOPHOS_ENDPOINT_STALE_DAYS} days or missing last-seen data."
        )
    if isolated > 0:
        recommendations.append(
            f"Review the business and incident status of {isolated:,} isolated endpoints before unisolating them, and ensure containment actions are documented."
        )
    if unenrolled > 0:
        recommendations.append(
            f"Review {unenrolled:,} unenrolled endpoint records and confirm whether they should be re-onboarded or removed as stale inventory."
        )
    if unknown_health > 0:
        recommendations.append(
            f"Resolve health visibility gaps for {unknown_health:,} endpoints reporting an unknown or unavailable health state."
        )

    failed_audits = int(audit.get("failed", 0) or 0)
    if failed_audits > 0:
        recommendations.append(
            f"Investigate {failed_audits:,} failed, denied, or error-status response/audit actions and verify whether retries or permission corrections are required."
        )
    elif int(audit.get("total", 0) or 0) > 0:
        positives.append("Sophos response and administrative activity is being captured in the dedicated audit index.")

    outbreak_count = int(outbreaks.get("total", 0) or 0)
    outbreak_threats = int(outbreaks.get("threats", 0) or 0)
    if outbreak_count > 0:
        recommendations.append(
            f"Investigate {outbreak_count:,} outbreak correlation records covering {outbreak_threats:,} threats; validate common indicators, affected endpoints, and containment scope."
        )
    else:
        positives.append("No Sophos outbreak correlation records were identified in the selected reporting period.")

    if not recommendations:
        recommendations.append(
            "No urgent Sophos remediation item was identified from the available telemetry. Continue daily monitoring, validate endpoint coverage, and compare trends across reporting periods."
        )

    return {
        "recommendations": recommendations,
        "positive_observations": positives or [
            "Sophos telemetry is available across alerts/events, endpoint inventory, audit activity, and outbreak correlation indices."
        ],
    }


def build_ai_insights_html(ai_analysis):
    if not ai_analysis:
        return ""

    risk = str(ai_analysis.get("overall_risk_rating", "N/A")).capitalize()
    risk_color = {
        "Critical": "#991b1b",
        "High": "#dc2626",
        "Medium": "#d97706",
        "Low": "#059669",
    }.get(risk, "#6b7280")

    def list_html(items):
        if not items:
            return "<li style='margin:4px 0;color:#6b7280;'>No specific items available.</li>"
        return "".join(
            f"<li style='margin:5px 0;'>{html.escape(str(item))}</li>"
            for item in safe_list(items)
        )

    executive = str(ai_analysis.get("executive_summary", "No executive summary available."))
    paragraphs = [part.strip() for part in executive.split("\n") if part.strip()]
    executive_html = "".join(f"<p style='margin:6px 0;'>{html.escape(part)}</p>" for part in paragraphs)

    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f0f9ff;border:1px solid #bfdbfe;border-radius:8px;margin:18px 0;">
      <tr><td style="background:#0d47a1;padding:12px 20px;border-top-left-radius:8px;border-top-right-radius:8px;">
        <h2 style="margin:0;color:#fff;font-size:16px;font-weight:700;">Athena-AI Insights</h2>
      </td></tr>
      <tr><td style="padding:20px;color:#1e293b;font-size:14px;line-height:1.6;">
        <div style="margin-bottom:18px;">
          <span style="background:{risk_color};color:#fff;padding:5px 12px;border-radius:14px;font-size:13px;font-weight:700;">Overall Risk Rating: {html.escape(risk)}</span>
        </div>
        <div style="margin-bottom:16px;"><strong>Executive Summary:</strong>{executive_html}</div>
        <div style="margin-bottom:16px;"><strong>Key Findings:</strong><ul style="margin:6px 0;padding-left:20px;">{list_html(ai_analysis.get('key_findings'))}</ul></div>
        <div style="margin-bottom:16px;background:#ecfdf5;padding:12px;border-radius:6px;border-left:4px solid #059669;">
          <strong style="color:#065f46;">Endpoint Posture:</strong>
          <ul style="margin:6px 0;padding-left:20px;">{list_html(ai_analysis.get('endpoint_posture'))}</ul>
        </div>
        <div style="margin-bottom:16px;background:#fff7ed;padding:12px;border-radius:6px;border-left:4px solid #d97706;">
          <strong style="color:#92400e;">Threat Observations:</strong>
          <ul style="margin:6px 0;padding-left:20px;">{list_html(ai_analysis.get('threat_observations'))}</ul>
        </div>
        <div style="margin-bottom:16px;background:#eff6ff;padding:12px;border-radius:6px;border-left:4px solid #2563eb;">
          <strong style="color:#1e40af;">Operational Observations:</strong>
          <ul style="margin:6px 0;padding-left:20px;">{list_html(ai_analysis.get('operational_observations'))}</ul>
        </div>
        <div><strong>Recommended Actions:</strong><ol style="margin:6px 0;padding-left:20px;">{list_html(ai_analysis.get('recommended_actions'))}</ol></div>
      </td></tr>
    </table>
    """


def build_recommendations_html(recommendation_data):
    def list_items(items):
        return "".join(
            f"<li style='margin:6px 0;'>{html.escape(str(item))}</li>"
            for item in safe_list(items)
        )

    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;margin:18px 0;">
      <tr><td style="background:#0f766e;padding:12px 20px;border-top-left-radius:8px;border-top-right-radius:8px;">
        <h2 style="margin:0;color:#fff;font-size:16px;font-weight:700;">Sophos Security &amp; Operational Recommendations</h2>
      </td></tr>
      <tr><td style="padding:20px;color:#1e293b;font-size:14px;line-height:1.6;">
        <div style="background:#ecfdf5;border-left:4px solid #059669;padding:12px;border-radius:6px;margin-bottom:16px;">
          <strong style="color:#065f46;">Positive Observations:</strong>
          <ul style="margin:8px 0 0 0;padding-left:20px;">{list_items(recommendation_data.get('positive_observations'))}</ul>
        </div>
        <div style="background:#fff7ed;border-left:4px solid #d97706;padding:12px;border-radius:6px;">
          <strong style="color:#92400e;">Prioritized Recommendations:</strong>
          <ol style="margin:8px 0 0 0;padding-left:20px;">{list_items(recommendation_data.get('recommendations'))}</ol>
        </div>
      </td></tr>
    </table>
    """


def build_recent_alert_rows(records):
    if not records:
        return "<tr><td colspan='6' style='padding:10px;color:#6b7280;'>No high-severity or alert-type records found.</td></tr>"
    rows = []
    for record in records[:MAX_DETAIL_ROWS]:
        event_or_alert = record.get("event_type") or record.get("alert_type") or record.get("record_type") or "N/A"
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;white-space:nowrap;'>{html.escape(fmt_datetime(record.get('created_at')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;font-weight:700;'>{html.escape(str(record.get('severity', 'Unknown')).title())}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(str(record.get('endpoint_name') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-word;'>{html.escape(truncate(event_or_alert, 70))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(str(record.get('status') or 'N/A'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-word;'>{html.escape(truncate(record.get('description'), 150))}</td>"
            "</tr>"
        )
    return "".join(rows)


def build_endpoint_rows(records):
    if not records:
        return "<tr><td colspan='7' style='padding:10px;color:#6b7280;'>No endpoint attention records found.</td></tr>"
    rows = []
    for record in records[:MAX_DETAIL_ROWS]:
        ip_text = ", ".join(str(item) for item in safe_list(record.get("ip_addresses"))) or "N/A"
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600;'>{html.escape(str(record.get('hostname') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(truncate(record.get('os') or record.get('os_family') or 'Unknown', 60))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(str(record.get('health_status') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(str(record.get('isolation_status') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:600;'>{fmt_num(record.get('threat_count', 0))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(fmt_datetime(record.get('last_seen_at')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-word;'>{html.escape(truncate(ip_text, 80))}</td>"
            "</tr>"
        )
    return "".join(rows)


def build_audit_rows(records):
    if not records:
        return "<tr><td colspan='6' style='padding:10px;color:#6b7280;'>No audit activity found.</td></tr>"
    rows = []
    for record in records[:MAX_DETAIL_ROWS]:
        target = record.get("endpoint_id") or record.get("alert_id") or record.get("command_id") or "N/A"
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;white-space:nowrap;'>{html.escape(fmt_datetime(record.get('timestamp')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600;'>{html.escape(str(record.get('action') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(str(record.get('performed_by') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(str(record.get('status') or 'Unknown'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-all;'>{html.escape(truncate(target, 60))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-word;'>{html.escape(truncate(record.get('message'), 130))}</td>"
            "</tr>"
        )
    return "".join(rows)


def build_outbreak_rows(records):
    if not records:
        return "<tr><td colspan='6' style='padding:10px;color:#6b7280;'>No outbreak correlation records found.</td></tr>"
    rows = []
    for record in records[:MAX_DETAIL_ROWS]:
        alert_ids = safe_list(record.get("alert_ids"))
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;word-break:break-all;'>{html.escape(truncate(record.get('outbreak_id'), 55))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:700;'>{fmt_num(record.get('threat_count', 0))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(fmt_datetime(record.get('window_start')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(fmt_datetime(record.get('window_end')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;'>{html.escape(fmt_datetime(record.get('correlated_at')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e5e7eb;text-align:right;'>{fmt_num(len(alert_ids))}</td>"
            "</tr>"
        )
    return "".join(rows)


def build_html_report(report_type, time_from, time_to, stats, ai_analysis=None):
    from_date = datetime.fromisoformat(time_from.replace("Z", "+00:00")).strftime("%B %d, %Y %H:%M UTC")
    to_date = datetime.fromisoformat(time_to.replace("Z", "+00:00")).strftime("%B %d, %Y %H:%M UTC")

    overview_cards = f"""
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      {card('Sophos Records', fmt_num(stats['overall']['sophos_records']), f"Alerts: {fmt_num(stats['overall']['alert_records'])} | Events: {fmt_num(stats['overall']['event_records'])}", '#1e40af')}
      {card('High / Critical', fmt_num(stats['overall']['high_or_critical']), f"Critical: {fmt_num(stats['overall']['critical'])}", '#dc2626')}
      {card('Total Endpoints', fmt_num(stats['overall']['total_endpoints']), f"Healthy: {fmt_num(stats['overall']['healthy_endpoints'])}", '#059669')}
      {card('At-Risk Endpoints', fmt_num(stats['overall']['at_risk_endpoints']), f"With threats: {fmt_num(stats['overall']['threatened_endpoints'])}", '#d97706')}
    </tr><tr>
      {card('Active Alerts', fmt_num(stats['overall']['active_alerts']), f"Unacknowledged: {fmt_num(stats['alerts']['unacknowledged'])}", '#be123c')}
      {card('Stale Endpoints', fmt_num(stats['overall']['stale_endpoints']), f"> {SOPHOS_ENDPOINT_STALE_DAYS} days / missing last seen", '#7c3aed')}
      {card('Audit Actions', fmt_num(stats['overall']['audit_actions']), f"Failed/denied: {fmt_num(stats['overall']['failed_audits'])}", '#0284c7')}
      {card('Outbreaks', fmt_num(stats['overall']['outbreaks']), f"Correlated threats: {fmt_num(stats['overall']['outbreak_threats'])}", '#991b1b')}
    </tr></table>
    """

    event_analytics_body = f"""
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>Severity Distribution</h4><table width="100%">{table_rows_from_dict(stats['alerts']['severities'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Record Types</h4><table width="100%">{table_rows_from_dict(stats['alerts']['record_types'])}</table></td>
    </tr><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>Top Event Types</h4><table width="100%">{table_rows_from_dict(stats['alerts']['event_types'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Top Alert Types</h4><table width="100%">{table_rows_from_dict(stats['alerts']['alert_types'])}</table></td>
    </tr><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>Top Affected Endpoints</h4><table width="100%">{table_rows_from_dict(stats['alerts']['top_endpoints'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Top Descriptions</h4><table width="100%">{table_rows_from_dict(stats['alerts']['top_descriptions'])}</table></td>
    </tr></table>
    """

    endpoint_posture_body = f"""
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>Health Status</h4><table width="100%">{table_rows_from_dict(stats['endpoints']['health_status'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Isolation Status</h4><table width="100%">{table_rows_from_dict(stats['endpoints']['isolation_status'])}</table></td>
    </tr><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>OS Family</h4><table width="100%">{table_rows_from_dict(stats['endpoints']['os_family'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Enrollment Status</h4><table width="100%">{table_rows_from_dict(stats['endpoints']['enrolled'])}</table></td>
    </tr></table>
    <p style="font-size:13px;color:#374151;line-height:1.6;">
      <strong>Current Endpoint Snapshot:</strong>
      Total threat count {fmt_num(stats['endpoints']['threat_count_total'])};
      endpoints with threats {fmt_num(stats['endpoints']['with_threats'])};
      isolated endpoints {fmt_num(stats['endpoints']['isolated'])};
      recently seen endpoints {fmt_num(stats['endpoints']['recently_seen'])};
      stale/missing last-seen endpoints {fmt_num(stats['endpoints']['stale'])}.
    </p>
    <h4 style="margin-top:18px;">Endpoints Requiring Attention</h4>
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f8fafc;">
        <th style="padding:8px;text-align:left;">Hostname</th><th style="padding:8px;text-align:left;">OS</th>
        <th style="padding:8px;text-align:left;">Health</th><th style="padding:8px;text-align:left;">Isolation</th>
        <th style="padding:8px;text-align:right;">Threats</th><th style="padding:8px;text-align:left;">Last Seen</th>
        <th style="padding:8px;text-align:left;">IP Addresses</th>
      </tr></thead>
      <tbody>{build_endpoint_rows(stats['endpoints']['attention_required'])}</tbody>
    </table>
    """

    important_alerts_body = f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f8fafc;">
        <th style="padding:8px;text-align:left;">Time</th><th style="padding:8px;text-align:left;">Severity</th>
        <th style="padding:8px;text-align:left;">Endpoint</th><th style="padding:8px;text-align:left;">Type</th>
        <th style="padding:8px;text-align:left;">Status</th><th style="padding:8px;text-align:left;">Description</th>
      </tr></thead>
      <tbody>{build_recent_alert_rows(stats['alerts']['recent'])}</tbody>
    </table>
    """

    audit_body = f"""
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>Top Actions</h4><table width="100%">{table_rows_from_dict(stats['audit']['actions'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Action Status</h4><table width="100%">{table_rows_from_dict(stats['audit']['statuses'])}</table></td>
    </tr><tr>
      <td width="50%" style="vertical-align:top;padding-right:10px;"><h4>Performed By</h4><table width="100%">{table_rows_from_dict(stats['audit']['performed_by'])}</table></td>
      <td width="50%" style="vertical-align:top;padding-left:10px;"><h4>Source IPs</h4><table width="100%">{table_rows_from_dict(stats['audit']['source_ips'])}</table></td>
    </tr></table>
    <p style="font-size:13px;color:#374151;line-height:1.6;">
      <strong>Audit Coverage:</strong> Endpoint-related actions {fmt_num(stats['audit']['endpoint_actions'])};
      alert-related actions {fmt_num(stats['audit']['alert_actions'])};
      command-related actions {fmt_num(stats['audit']['command_actions'])}.
    </p>
    <h4 style="margin-top:18px;">Recent Audit Activity</h4>
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f8fafc;">
        <th style="padding:8px;text-align:left;">Time</th><th style="padding:8px;text-align:left;">Action</th>
        <th style="padding:8px;text-align:left;">Performed By</th><th style="padding:8px;text-align:left;">Status</th>
        <th style="padding:8px;text-align:left;">Target</th><th style="padding:8px;text-align:left;">Message</th>
      </tr></thead>
      <tbody>{build_audit_rows(stats['audit']['recent'])}</tbody>
    </table>
    """

    outbreak_body = f"""
    <p style="font-size:13px;color:#374151;line-height:1.6;">
      <strong>Outbreak Summary:</strong> {fmt_num(stats['outbreaks']['total'])} outbreak records,
      {fmt_num(stats['outbreaks']['threats'])} total correlated threats,
      maximum {fmt_num(stats['outbreaks']['max_threats'])} threats in one outbreak,
      average {stats['outbreaks']['average_threats']:.1f} threats per outbreak.
    </p>
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f8fafc;">
        <th style="padding:8px;text-align:left;">Outbreak ID</th><th style="padding:8px;text-align:right;">Threats</th>
        <th style="padding:8px;text-align:left;">Window Start</th><th style="padding:8px;text-align:left;">Window End</th>
        <th style="padding:8px;text-align:left;">Correlated At</th><th style="padding:8px;text-align:right;">Alert IDs</th>
      </tr></thead>
      <tbody>{build_outbreak_rows(stats['outbreaks']['recent'])}</tbody>
    </table>
    """

    recommendation_data = build_sophos_recommendations(stats)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Arial,sans-serif;color:#374151;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;"><tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:1180px;background:#f8fafc;">
      <tr><td style="background:#0d47a1;color:#fff;padding:16px 22px;">
        <div style="font-size:20px;font-weight:700;">{html.escape(ATHENA_NAME)} — {html.escape(report_type.title())} Sophos Central Report</div>
        <div style="font-size:12px;margin-top:5px;">Tenant: {html.escape(TENANT_NAME)}</div>
        <div style="font-size:12px;margin-top:5px;">Period: {html.escape(from_date)} — {html.escape(to_date)}</div>
      </td></tr>
      <tr><td style="padding:18px 22px;">
        <p style="margin:0 0 16px 0;line-height:1.6;">This automated report combines Sophos Central alert/event telemetry, current endpoint posture, response and administrative audit activity, and outbreak correlation data from the Athena Sophos indices.</p>
        {overview_cards}
        {build_ai_insights_html(ai_analysis)}
        {build_recommendations_html(recommendation_data)}
        {section('Sophos Alert and Event Analytics', event_analytics_body)}
        {section('Recent Important Alerts and Events', important_alerts_body)}
        {section('Endpoint Health and Protection Posture', endpoint_posture_body)}
        {section('Response and Administrative Audit Activity', audit_body)}
        {section('Outbreak Correlation', outbreak_body)}
      </td></tr>
      <tr><td style="background:#f3f4f6;color:#333;padding:12px 18px;font-size:12px;">
        <p style="margin:2px 0 6px 0;"><strong>Athena Security Group</strong></p>
        <p style="margin:2px 0;">🌐 <a href="{html.escape(ATHENA_WEBSITE)}" style="color:#0d47a1;text-decoration:none;">Website</a>
        &nbsp;|&nbsp; 📄 <a href="{html.escape(ATHENA_DOCS)}" style="color:#0d47a1;text-decoration:none;">Docs</a>
        &nbsp;|&nbsp; 📧 <a href="mailto:{html.escape(ATHENA_SUPPORT)}" style="color:#0d47a1;text-decoration:none;">{html.escape(ATHENA_SUPPORT)}</a></p>
        <p style="margin:10px 0 0 0;">Generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %I:%M %p UTC')}. Endpoint metrics represent the current indexed endpoint snapshot; alert, audit, and outbreak metrics follow the selected reporting window.</p>
      </td></tr>
    </table>
  </td></tr></table>
</body>
</html>"""


def build_plain_report(report_type, time_from, time_to, stats, ai_analysis=None):
    lines = [
        "=" * 88,
        f"{ATHENA_NAME} - {report_type.upper()} SOPHOS CENTRAL REPORT",
        "=" * 88,
        f"Tenant: {TENANT_NAME}",
        f"Period: {time_from} to {time_to}",
        "",
        "SUMMARY",
        f"Sophos Records: {fmt_num(stats['overall']['sophos_records'])}",
        f"Alert Records: {fmt_num(stats['overall']['alert_records'])}",
        f"Event Records: {fmt_num(stats['overall']['event_records'])}",
        f"High/Critical Records: {fmt_num(stats['overall']['high_or_critical'])}",
        f"Critical Records: {fmt_num(stats['overall']['critical'])}",
        f"Active Alerts: {fmt_num(stats['overall']['active_alerts'])}",
        f"Total Endpoints: {fmt_num(stats['overall']['total_endpoints'])}",
        f"Healthy Endpoints: {fmt_num(stats['overall']['healthy_endpoints'])}",
        f"At-Risk Endpoints: {fmt_num(stats['overall']['at_risk_endpoints'])}",
        f"Endpoints With Threats: {fmt_num(stats['overall']['threatened_endpoints'])}",
        f"Stale Endpoints: {fmt_num(stats['overall']['stale_endpoints'])}",
        f"Audit Actions: {fmt_num(stats['overall']['audit_actions'])}",
        f"Failed Audit Actions: {fmt_num(stats['overall']['failed_audits'])}",
        f"Outbreaks: {fmt_num(stats['overall']['outbreaks'])}",
        f"Outbreak Threats: {fmt_num(stats['overall']['outbreak_threats'])}",
        "",
    ]

    if ai_analysis:
        lines.extend([
            "ATHENA-AI INSIGHTS",
            "-" * 88,
            f"Overall Risk Rating: {ai_analysis.get('overall_risk_rating', 'N/A')}",
            str(ai_analysis.get("executive_summary", "")),
            "",
            "Key Findings:",
        ])
        for item in safe_list(ai_analysis.get("key_findings")):
            lines.append(f"  - {item}")
        lines.append("")
        lines.append("Recommended Actions:")
        for item in safe_list(ai_analysis.get("recommended_actions")):
            lines.append(f"  - {item}")
        lines.append("")

    recommendation_data = build_sophos_recommendations(stats)
    lines.extend(["SOPHOS SECURITY & OPERATIONAL RECOMMENDATIONS", "-" * 88])
    for item in recommendation_data.get("recommendations", []):
        lines.append(f"  - {item}")

    lines.extend(["", "SEVERITY DISTRIBUTION"])
    for key, value in sorted(stats["alerts"]["severities"].items(), key=lambda item: item[1], reverse=True):
        lines.append(f"  {key}: {fmt_num(value)}")

    lines.extend(["", "TOP EVENT TYPES"])
    for key, value in sorted(stats["alerts"]["event_types"].items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {key}: {fmt_num(value)}")

    lines.extend(["", "ENDPOINT HEALTH"])
    for key, value in sorted(stats["endpoints"]["health_status"].items(), key=lambda item: item[1], reverse=True):
        lines.append(f"  {key}: {fmt_num(value)}")

    lines.extend(["", "AUDIT ACTIONS"])
    for key, value in sorted(stats["audit"]["actions"].items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {key}: {fmt_num(value)}")

    lines.extend(["", f"Generated on {datetime.now(timezone.utc).isoformat()}"])
    return "\n".join(lines)


def save_report_files(report_type, time_from, html_body, plain_body):
    try:
        os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
        date_label = datetime.fromisoformat(time_from.replace("Z", "+00:00")).strftime("%Y%m%d")
        base_name = f"sophos_{report_type}_{date_label}"
        html_path = os.path.join(REPORT_OUTPUT_DIR, f"{base_name}.html")
        text_path = os.path.join(REPORT_OUTPUT_DIR, f"{base_name}.txt")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html_body)
        with open(text_path, "w", encoding="utf-8") as handle:
            handle.write(plain_body)
        log(f"Saved Sophos report files: {html_path}, {text_path}")
        return html_path, text_path
    except Exception as exc:
        log(f"Failed to save Sophos report files: {exc}")
        return None, None


def send_email(recipients, subject, plain_body, html_body):
    try:
        if not recipients:
            log("No SMTP recipients configured; report email was not sent")
            return False

        message = EmailMessage()
        message["Subject"] = subject
        message["To"] = ", ".join(recipients)
        message["From"] = formataddr((f"{ATHENA_NAME} Reports", SMTP_FROM))
        message.set_content(plain_body)
        message.add_alternative(html_body, subtype="html")

        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.ehlo()
        if SMTP_USE_TLS and not SMTP_USE_SSL:
            server.starttls()
            server.ehlo()
        if SMTP_USERNAME and SMTP_PASSWORD:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)
        server.quit()
        log(f"Sophos Central report sent successfully to {recipients}")
        return True
    except Exception as exc:
        log(f"Error sending Sophos Central report email: {exc}")
        return False


def generate_report(report_type, time_from, time_to, recipients):
    log(f"Generating {report_type} Sophos Central report from {time_from} to {time_to}")
    stats = collect_stats(time_from, time_to, include_endpoint_details=True)

    previous_from, previous_to = calculate_previous_period(time_from, time_to)
    # Endpoint inventory is current-state data, so previous-period collection is used only
    # for alert/event, audit, and outbreak trend keys.
    previous_stats = collect_stats(previous_from, previous_to, include_endpoint_details=False)
    add_comparison(stats, previous_stats)

    if not any(int(value or 0) for value in stats.get("overall", {}).values()):
        log("No Sophos Central data found across the configured indices")
        return False

    ai_analysis = (
        get_ai_sophos_insights(stats, report_type, time_from, time_to)
        or build_rule_based_ai_insights(stats)
    )
    log("Athena-AI Insights section prepared for Sophos Central report")

    subject_date = datetime.fromisoformat(time_from.replace("Z", "+00:00")).strftime("%b %d, %Y")
    subject = f"[{TENANT_NAME}] Athena SOC {report_type.title()} Sophos Central Report - {subject_date}"
    html_body = build_html_report(report_type, time_from, time_to, stats, ai_analysis)
    plain_body = build_plain_report(report_type, time_from, time_to, stats, ai_analysis)

    saved = False
    if REPORT_SOPHOS_SAVE_OUTPUT or not REPORT_SOPHOS_SEND_EMAIL:
        html_path, text_path = save_report_files(report_type, time_from, html_body, plain_body)
        saved = bool(html_path and text_path)

    if REPORT_SOPHOS_SEND_EMAIL:
        delivered = send_email(recipients, subject, plain_body, html_body)
        if not delivered and not saved:
            log("Email delivery failed; saving a local copy of the generated Sophos report")
            html_path, text_path = save_report_files(report_type, time_from, html_body, plain_body)
            saved = bool(html_path and text_path)
        return delivered

    log("REPORT_SOPHOS_SEND_EMAIL=false; report generation completed without email delivery")
    return saved


def normalize_custom_time(value):
    """Allow ISO timestamps with or without Z and normalize UTC values."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def main(args):
    if not REPORT_SOPHOS_ENABLED:
        log("REPORT_SOPHOS_ENABLED=false; skipping Sophos Central report")
        return

    if len(args) < 2:
        log("Usage: reports_sophos.py <daily|weekly|monthly|custom> [start_time] [end_time]")
        return

    report_type = args[1].lower()
    now = datetime.now(timezone.utc)

    if report_type == "daily":
        time_to = now.isoformat().replace("+00:00", "Z")
        time_from = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    elif report_type == "weekly":
        time_to = now.isoformat().replace("+00:00", "Z")
        time_from = (now - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    elif report_type == "monthly":
        time_to = now.isoformat().replace("+00:00", "Z")
        time_from = (now - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    elif report_type == "custom":
        if len(args) < 4:
            log("Custom report requires: reports_sophos.py custom <start_time> <end_time>")
            return
        try:
            time_from = normalize_custom_time(args[2])
            time_to = normalize_custom_time(args[3])
        except ValueError as exc:
            log(f"Invalid custom timestamp: {exc}")
            return
    else:
        log(f"Unknown report type: {report_type}")
        return

    log(f"Recipients: {SMTP_RECIPIENT}")
    success = generate_report(report_type, time_from, time_to, SMTP_RECIPIENT)
    if not success:
        log("Sophos Central report generation or delivery did not complete successfully")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as exc:
        import traceback

        log(f"Unhandled exception: {exc}")
        log(traceback.format_exc())
        raise
