#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
Athena SOC - Concise Sophos Central Report
------------------------------------------
Produces an action-focused report from:
  - athena-sophos-alerts*
  - athena-sophos-endpoints*
  - athena-sophos-audit*
  - athena-sophos-outbreaks* (count only; no detailed outbreak section)

The report intentionally excludes:
  - low/informational Sophos events
  - successful audit activity
  - zero-value risk metrics
  - large telemetry breakdowns that do not require SOC action

Usage:
  python3 reports_sophos.py daily
  python3 reports_sophos.py weekly
  python3 reports_sophos.py monthly
  python3 reports_sophos.py custom 2026-06-01T00:00:00Z 2026-06-21T23:59:59Z

Test without email:
  REPORT_SOPHOS_SEND_EMAIL=false REPORT_SOPHOS_SAVE_OUTPUT=true \
    python3 reports_sophos.py daily
"""

import html
import json
# BUILD: SOC-CONCISE-V6 - includes Athena-AI Narrative and Sophos Security & Operational Recommendations
import os
import smtplib
import sys
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr

from dotenv import load_dotenv

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))
load_dotenv()

# -----------------------------------------------------------------------------
# General configuration
# -----------------------------------------------------------------------------
ATHENA_NAME = os.getenv("ATHENA_NAME", "Athena SOC")
TENANT_NAME = os.getenv("TENANT_NAME", "test.athenasecuritygrp.com")
ATHENA_WEBSITE = os.getenv("ATHENA_WEBSITE", "https://athenasoftwaregroup.ai/")
ATHENA_DOCS = os.getenv("ATHENA_DOCS", "https://athenasoftwaregroup.ai/")
ATHENA_SUPPORT = os.getenv("ATHENA_SUPPORT", "alerts@athena.athenasecuritygrp.com")

REPORT_SOPHOS_ENABLED = os.getenv("REPORT_SOPHOS_ENABLED", "true").lower() == "true"
REPORT_SOPHOS_SEND_EMAIL = os.getenv("REPORT_SOPHOS_SEND_EMAIL", "true").lower() == "true"
REPORT_SOPHOS_SAVE_OUTPUT = os.getenv("REPORT_SOPHOS_SAVE_OUTPUT", "false").lower() == "true"
REPORT_OUTPUT_DIR = os.getenv(
    "REPORT_OUTPUT_DIR", os.path.join(SCRIPT_DIR, "generated_reports")
)
REPORT_VERSION = "SOC-CONCISE-2026.06.22-v6"
MAX_DETAIL_ROWS = max(1, int(os.getenv("SOPHOS_MAX_DETAIL_ROWS", "10")))
SOPHOS_ENDPOINT_STALE_DAYS = max(
    1, int(os.getenv("SOPHOS_ENDPOINT_STALE_DAYS", "7"))
)

# -----------------------------------------------------------------------------
# SMTP
# -----------------------------------------------------------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() == "true"
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "alerts@athenasoftwaregrp.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME)
SMTP_RECIPIENT = [
    value.strip()
    for value in os.getenv(
        "SMTP_RECIPIENT", "mohammad@athenasecuritygrp.com"
    ).split(",")
    if value.strip()
]

# -----------------------------------------------------------------------------
# OpenSearch
# -----------------------------------------------------------------------------
ES_HOST = os.getenv("ES_HOST", "https://localhost:9200").rstrip("/")
ES_USERNAME = os.getenv("ES_USERNAME", "admin")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_VERIFY_SSL = os.getenv("ES_VERIFY_SSL", "false").lower() == "true"
ES_QUERY_TIMEOUT = int(os.getenv("ES_QUERY_TIMEOUT", "60"))

ES_INDEX_ALERTS = os.getenv(
    "ES_INDEX_PATTERN_SOPHOS_ALERTS", "athena-sophos-alerts*"
)
ES_INDEX_ENDPOINTS = os.getenv(
    "ES_INDEX_PATTERN_SOPHOS_ENDPOINTS", "athena-sophos-endpoints*"
)
ES_INDEX_AUDIT = os.getenv(
    "ES_INDEX_PATTERN_SOPHOS_AUDIT", "athena-sophos-audit*"
)
ES_INDEX_OUTBREAKS = os.getenv(
    "ES_INDEX_PATTERN_SOPHOS_OUTBREAKS", "athena-sophos-outbreaks*"
)

ALERT_TIME_FIELD = os.getenv("SOPHOS_ALERT_TIME_FIELD", "created_at")
AUDIT_TIME_FIELD = os.getenv("SOPHOS_AUDIT_TIME_FIELD", "timestamp")
OUTBREAK_TIME_FIELD = os.getenv("SOPHOS_OUTBREAK_TIME_FIELD", "correlated_at")

# -----------------------------------------------------------------------------
# Athena-AI
# -----------------------------------------------------------------------------
LLM_BASE_URL = os.getenv(
    "LLM_BASE_URL", "https://router.huggingface.co/v1"
).rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-ai/DeepSeek-V3.1-Terminus")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() == "true"
HF_ORG_NAME = os.getenv("HF_ORG_NAME", "").strip()
LLM_CHAT_URL = f"{LLM_BASE_URL}/chat/completions"

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "sophos_reporting.log")


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


# -----------------------------------------------------------------------------
# OpenSearch helpers
# -----------------------------------------------------------------------------
def es_search(index_pattern, query):
    import requests
    import urllib3
    from requests.auth import HTTPBasicAuth

    if not ES_VERIFY_SSL:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(
            f"{ES_HOST}/{index_pattern}/_search",
            params={"ignore_unavailable": "true", "allow_no_indices": "true"},
            json=query,
            auth=HTTPBasicAuth(ES_USERNAME, ES_PASSWORD)
            if ES_USERNAME or ES_PASSWORD
            else None,
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


def range_query(field, time_from, time_to):
    return {
        "range": {
            field: {
                "gte": time_from,
                "lte": time_to,
                "format": "strict_date_optional_time",
            }
        }
    }


def total_hits(response):
    total = (response or {}).get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        return int(total.get("value", 0) or 0)
    return int(total or 0)


def parse_hits(response):
    records = []
    for hit in (response or {}).get("hits", {}).get("hits", []):
        source = hit.get("_source", {}) or {}
        source["_index"] = hit.get("_index", "")
        records.append(source)
    return records


def lower(value):
    return str(value or "").strip().lower()


def as_int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def parse_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def format_timestamp(value):
    parsed = parse_datetime(value)
    if not parsed:
        return "N/A"
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def severity_rank(record):
    severity = lower(record.get("severity"))
    score = as_int(record.get("severity_score"))
    if severity == "critical" or score >= 4:
        return 4
    if severity == "high" or score == 3:
        return 3
    if severity == "medium" or score == 2:
        return 2
    if severity == "low" or score == 1:
        return 1
    return 0


def normalized_severity(record):
    rank = severity_rank(record)
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(
        rank, str(record.get("severity") or "Unknown").title()
    )


# -----------------------------------------------------------------------------
# Action-focused Sophos queries
# -----------------------------------------------------------------------------
def query_actionable_alerts(time_from, time_to):
    """Only high/critical Sophos records are relevant to this report."""
    high_critical_query = {
        "bool": {
            "should": [
                {
                    "terms": {
                        "severity": [
                            "high",
                            "critical",
                            "High",
                            "Critical",
                            "HIGH",
                            "CRITICAL",
                        ]
                    }
                },
                {"range": {"severity_score": {"gte": 3}}},
            ],
            "minimum_should_match": 1,
        }
    }

    query = {
        "size": MAX_DETAIL_ROWS,
        "track_total_hits": True,
        "_source": [
            "sophos_id",
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
            "source",
            "created_at",
            "xdr",
            "xdr_elevated",
        ],
        "query": {
            "bool": {
                "filter": [
                    range_query(ALERT_TIME_FIELD, time_from, time_to),
                    high_critical_query,
                ]
            }
        },
        "sort": [
            {"severity_score": {"order": "desc", "unmapped_type": "integer"}},
            {ALERT_TIME_FIELD: {"order": "desc", "unmapped_type": "date"}},
        ],
    }
    response = es_search(ES_INDEX_ALERTS, query)
    records = parse_hits(response)

    # Defensive filtering protects the report if source data has inconsistent casing.
    records = [record for record in records if severity_rank(record) >= 3]
    critical = sum(1 for record in records if severity_rank(record) >= 4)
    high = sum(1 for record in records if severity_rank(record) == 3)

    # When the result set exceeds MAX_DETAIL_ROWS, retrieve exact severity counts.
    count_query = {
        "size": 0,
        "track_total_hits": True,
        "query": query["query"],
        "aggs": {
            "critical": {
                "filter": {
                    "bool": {
                        "should": [
                            {
                                "terms": {
                                    "severity": [
                                        "critical",
                                        "Critical",
                                        "CRITICAL",
                                    ]
                                }
                            },
                            {"range": {"severity_score": {"gte": 4}}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
            "high": {
                "filter": {
                    "bool": {
                        "should": [
                            {
                                "terms": {
                                    "severity": ["high", "High", "HIGH"]
                                }
                            },
                            {"term": {"severity_score": 3}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            },
        },
    }
    count_response = es_search(ES_INDEX_ALERTS, count_query)
    aggs = count_response.get("aggregations", {}) if count_response else {}
    if aggs:
        critical = as_int(aggs.get("critical", {}).get("doc_count", critical))
        high = as_int(aggs.get("high", {}).get("doc_count", high))

    return {
        "total": total_hits(count_response or response),
        "critical": critical,
        "high": high,
        "records": records,
    }


def query_endpoint_snapshot():
    """Fetch the current endpoint snapshot. Endpoints are upserted by Sophos ID."""
    query = {
        "size": 10000,
        "track_total_hits": True,
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
        "query": {"match_all": {}},
        "sort": [
            {"last_seen_at": {"order": "desc", "unmapped_type": "date"}}
        ],
    }
    return parse_hits(es_search(ES_INDEX_ENDPOINTS, query))


def endpoint_attention_reason(endpoint, report_time_to):
    """Return only endpoint conditions that require SOC or operational action."""
    reasons = []
    health = lower(endpoint.get("health_status"))
    isolation = lower(endpoint.get("isolation_status"))
    threats = as_int(endpoint.get("threat_count"))
    enrolled = endpoint.get("enrolled")
    last_seen = parse_datetime(endpoint.get("last_seen_at")) or parse_datetime(endpoint.get("synced_at"))
    report_end = parse_datetime(report_time_to) or datetime.now(timezone.utc)

    healthy_values = {"good", "healthy", "green", "normal", "ok", "protected"}
    non_isolated_values = {
        "", "not_isolated", "not isolated", "false", "none", "normal", "notisolated"
    }

    if threats > 0:
        reasons.append(f"{threats} active threat(s) reported")
    if health and health not in healthy_values:
        reasons.append(f"Protection health is {endpoint.get('health_status')}")
    if enrolled is False or lower(enrolled) == "false":
        reasons.append("Endpoint is not enrolled")
    if isolation not in non_isolated_values:
        reasons.append("Endpoint is isolated; validate containment status")
    if last_seen and report_end - last_seen > timedelta(days=SOPHOS_ENDPOINT_STALE_DAYS):
        reasons.append(f"No Sophos check-in for more than {SOPHOS_ENDPOINT_STALE_DAYS} days")

    return reasons


def analyze_endpoints(endpoints, report_time_to):
    attention = []
    with_threats = 0
    stale = 0

    for endpoint in endpoints:
        reasons = endpoint_attention_reason(endpoint, report_time_to)
        threats = as_int(endpoint.get("threat_count"))

        if threats > 0:
            with_threats += 1
        if any("No Sophos check-in" in reason for reason in reasons):
            stale += 1

        if reasons:
            item = dict(endpoint)
            item["attention_reason"] = "; ".join(reasons)
            attention.append(item)

    attention.sort(
        key=lambda endpoint: (
            as_int(endpoint.get("threat_count")),
            "Protection health" in endpoint.get("attention_reason", ""),
            parse_datetime(endpoint.get("last_seen_at"))
            or parse_datetime(endpoint.get("synced_at"))
            or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )

    return {
        "attention_count": len(attention),
        "with_threats": with_threats,
        "stale": stale,
        "attention": attention[:MAX_DETAIL_ROWS],
    }


def query_failed_audit_actions(time_from, time_to):
    """Only failed, denied, rejected, or error audit actions are reported."""
    failure_values = [
        "failed",
        "failure",
        "denied",
        "error",
        "rejected",
        "unsuccessful",
        "Failed",
        "Failure",
        "Denied",
        "Error",
        "Rejected",
        "Unsuccessful",
        "FAILED",
        "FAILURE",
        "DENIED",
        "ERROR",
        "REJECTED",
        "UNSUCCESSFUL",
    ]
    query = {
        "size": MAX_DETAIL_ROWS,
        "track_total_hits": True,
        "_source": [
            "audit_id",
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
        "query": {
            "bool": {
                "filter": [
                    range_query(AUDIT_TIME_FIELD, time_from, time_to),
                    {"terms": {"status": failure_values}},
                ]
            }
        },
        "sort": [
            {AUDIT_TIME_FIELD: {"order": "desc", "unmapped_type": "date"}}
        ],
    }
    response = es_search(ES_INDEX_AUDIT, query)
    return {"total": total_hits(response), "records": parse_hits(response)}


def query_audit_activity_summary(time_from, time_to):
    """Return only the audit-record count for concise positive observations."""
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [range_query(AUDIT_TIME_FIELD, time_from, time_to)]
            }
        },
    }
    response = es_search(ES_INDEX_AUDIT, query)
    return {"total": total_hits(response)}


def query_outbreak_summary(time_from, time_to):
    """Return only the outbreak count; no detailed outbreak section is rendered."""
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [range_query(OUTBREAK_TIME_FIELD, time_from, time_to)]
            }
        },
    }
    response = es_search(ES_INDEX_OUTBREAKS, query)
    return {"total": total_hits(response)}


def collect_stats(time_from, time_to):
    alerts = query_actionable_alerts(time_from, time_to)
    endpoint_records = query_endpoint_snapshot()
    endpoints = analyze_endpoints(endpoint_records, time_to)
    failed_actions = query_failed_audit_actions(time_from, time_to)
    audit_activity = query_audit_activity_summary(time_from, time_to)
    outbreaks = query_outbreak_summary(time_from, time_to)

    stats = {
        "alerts": alerts,
        "endpoints": endpoints,
        "failed_actions": failed_actions,
        "audit_activity": audit_activity,
        "outbreaks": outbreaks,
    }
    stats["risk"] = determine_risk(stats)
    return stats


# -----------------------------------------------------------------------------
# SOC risk and recommendation logic
# -----------------------------------------------------------------------------
def determine_risk(stats):
    critical = stats["alerts"]["critical"]
    high = stats["alerts"]["high"]
    threat_endpoints = stats["endpoints"]["with_threats"]
    attention_endpoints = stats["endpoints"]["attention_count"]
    failed_actions = stats["failed_actions"]["total"]
    stale = stats["endpoints"]["stale"]

    if critical > 0:
        return "Critical"
    if high > 0 or threat_endpoints > 0:
        return "High"
    if attention_endpoints > 0 or failed_actions > 0 or stale > 0:
        return "Medium"
    return "Low"


def alert_specific_recommendation(record):
    event_type = lower(record.get("event_type"))
    description = lower(record.get("description"))
    endpoint = record.get("endpoint_name") or record.get("source") or "affected endpoint"

    if "machealth" in event_type or "macos" in description or "prerequisite" in description:
        return (
            f"Complete the required Sophos macOS prerequisites/MDM permissions on {endpoint}, "
            "then confirm the endpoint health returns to a protected state."
        )
    if "malware" in event_type or "threat" in event_type or "malware" in description:
        return (
            f"Triage the detection on {endpoint}, validate containment, run a full scan, "
            "and review the process/file lineage before closure."
        )
    if "tamper" in event_type or "tamper" in description:
        return (
            f"Validate the tamper-protection event on {endpoint} and confirm no unauthorized "
            "security-control changes occurred."
        )
    return (
        f"Investigate the {normalized_severity(record).lower()} Sophos finding on {endpoint} "
        "and document containment and closure evidence."
    )


def unique_items(items, limit=3):
    result = []
    seen = set()
    for item in items:
        text = str(item).strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            result.append(text)
        if len(result) >= limit:
            break
    return result


def build_posture_label(stats):
    """Return a concise posture statement based only on actionable conditions."""
    risk = stats["risk"]
    records = stats["alerts"]["records"]
    descriptions = " ".join(
        lower(record.get("description") or record.get("event_type"))
        for record in records
    )

    if risk == "Critical":
        return "Critical - Immediate SOC Action Required"
    if risk == "High":
        if "machealth" in descriptions or "prerequisite" in descriptions or "macos" in descriptions:
            return "High - Endpoint Protection Gap"
        if stats["endpoints"]["with_threats"] > 0:
            return "High - Active Endpoint Threat"
        return "High - Degraded Protection"
    if risk == "Medium":
        if stats["failed_actions"]["total"] > 0:
            return "Medium - Response Action Attention"
        return "Medium - Protection Attention Required"
    return "Low - Stable Sophos Posture"


def build_rule_based_soc_assessment(stats):
    """Create a concise SOC narrative when the external LLM is unavailable."""
    alerts = stats["alerts"]
    endpoints = stats["endpoints"]
    failures = stats["failed_actions"]
    risk = stats["risk"]
    posture = build_posture_label(stats)

    findings = []
    actions = []

    for record in alerts["records"]:
        endpoint = record.get("endpoint_name") or record.get("source") or "Affected endpoint"
        finding = (
            record.get("description")
            or record.get("event_type")
            or record.get("alert_type")
            or "Sophos finding"
        )
        findings.append(f"{endpoint}: {finding}")
        actions.append(alert_specific_recommendation(record))

    alerted_endpoints = {
        lower(record.get("endpoint_name") or record.get("source"))
        for record in alerts["records"]
        if record.get("endpoint_name") or record.get("source")
    }

    for endpoint in endpoints["attention"]:
        hostname = endpoint.get("hostname") or endpoint.get("sophos_id") or "Endpoint"
        reason = endpoint.get("attention_reason", "Requires action")
        if lower(hostname) not in alerted_endpoints or as_int(endpoint.get("threat_count")) > 0:
            findings.append(f"{hostname}: {reason}")

        if as_int(endpoint.get("threat_count")) > 0:
            actions.append(
                f"Triage {hostname}, run a full Sophos scan, and isolate it if compromise is suspected."
            )
        elif "Protection health" in reason:
            actions.append(f"Restore Sophos protection on {hostname} and verify healthy status in Sophos Central.")
        elif "No Sophos check-in" in reason:
            actions.append(f"Restore Sophos service/connectivity on {hostname} and confirm a new check-in.")
        elif "not enrolled" in lower(reason):
            actions.append(f"Re-enroll {hostname} and confirm the correct Sophos policy assignment.")
        elif "isolated" in lower(reason):
            actions.append(f"Validate whether isolation on {hostname} is still required before release.")

    for record in failures["records"]:
        action_name = record.get("action") or "Sophos action"
        target = record.get("endpoint_id") or record.get("alert_id") or record.get("command_id") or "target"
        error = record.get("message") or record.get("status") or "Action failed"
        findings.append(f"{action_name} failed for {target}: {error}")

    if failures["total"] > 0:
        actions.append(
            "Validate Sophos API role permissions, endpoint connectivity, and command status before retrying failed actions."
        )

    findings = unique_items(findings, 3)
    actions = unique_items(actions, 3)

    if risk == "Critical":
        narrative = (
            "The Sophos Central posture is critical because one or more findings indicate immediate security exposure. "
            "Prioritize containment, endpoint validation, and evidence-based closure before the affected systems return to normal operation."
        )
    elif risk == "High":
        if alerts["high"] > 0 and endpoints["with_threats"] > 0:
            narrative = (
                "The Sophos Central posture is high due to high-severity detections and active endpoint threat conditions. "
                "Affected endpoints may remain exposed until containment, scanning, and protection-health validation are completed."
            )
        elif alerts["high"] > 0:
            narrative = (
                "The Sophos Central posture is high because a high-severity protection condition requires remediation. "
                "The affected endpoint may not be fully protected until the identified prerequisite or security-control gap is resolved and health is revalidated."
            )
        else:
            narrative = (
                "The Sophos Central posture is high because an endpoint reports an active threat condition. "
                "Immediate triage, scanning, and containment validation are required."
            )
    elif risk == "Medium":
        narrative = (
            "The Sophos Central posture requires attention because endpoint protection health, connectivity, enrollment, isolation, or response-action execution is not in the expected state. "
            "Remediation should focus on restoring protection and confirming successful control operation."
        )
    else:
        narrative = "The Sophos Central posture is stable, with no condition requiring SOC action during the reporting period."

    return {
        "overall_posture": posture,
        "narrative": narrative,
        "key_findings": findings,
        "recommended_actions": actions,
    }


def build_llm_headers():
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_API_KEY}",
    }
    if HF_ORG_NAME:
        headers["X-HF-Bill-To"] = HF_ORG_NAME
    return headers


def parse_llm_json(content):
    if not content or not content.strip():
        return None
    text = content.strip()
    if text.startswith("```"):
        text = text[3:]
        if text.lower().startswith("json"):
            text = text[4:]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            try:
                return json.loads(text[first : last + 1])
            except json.JSONDecodeError:
                return None
    return None


def get_ai_soc_assessment(stats, report_type, time_from, time_to):
    """Return a short, action-focused SOC assessment. No informational filler."""
    if not LLM_ENABLED or not LLM_API_KEY:
        if not LLM_API_KEY:
            log("LLM_API_KEY is not set; using rule-based Athena-AI Insights")
        return None

    import requests

    alert_lines = []
    for record in stats["alerts"]["records"][:5]:
        alert_lines.append(
            {
                "severity": normalized_severity(record),
                "endpoint": record.get("endpoint_name") or record.get("source"),
                "type": record.get("event_type") or record.get("alert_type"),
                "description": record.get("description"),
                "status": record.get("status"),
            }
        )

    endpoint_lines = []
    for endpoint in stats["endpoints"]["attention"][:5]:
        endpoint_lines.append(
            {
                "hostname": endpoint.get("hostname"),
                "os": endpoint.get("os_family") or endpoint.get("os"),
                "health": endpoint.get("health_status"),
                "threat_count": as_int(endpoint.get("threat_count")),
                "reason": endpoint.get("attention_reason"),
            }
        )

    prompt_data = {
        "period": {"type": report_type, "from": time_from, "to": time_to},
        "risk": stats["risk"],
        "critical_alerts": stats["alerts"]["critical"],
        "high_alerts": stats["alerts"]["high"],
        "endpoints_requiring_attention": stats["endpoints"]["attention_count"],
        "endpoints_with_threats": stats["endpoints"]["with_threats"],
        "stale_endpoints": stats["endpoints"]["stale"],
        "failed_actions": stats["failed_actions"]["total"],
        "important_alerts": alert_lines,
        "affected_endpoints": endpoint_lines,
    }

    prompt = f"""You are Athena-AI acting as a senior SOC analyst reviewing Sophos Central telemetry.

Create a concise, decision-oriented SOC narrative from this JSON:
{json.dumps(prompt_data, ensure_ascii=False)}

Strict rules:
- Do not mention any metric whose value is zero.
- Do not mention low, informational, successful-update, normal, or healthy activity.
- Do not restate the complete dataset.
- Explain the current protection posture, supported security impact, and what requires action.
- Keep the narrative to a maximum of 3 short sentences.
- Provide no more than 3 key findings and no more than 3 prioritized recommendations.
- Recommendations must be specific to the supplied Sophos finding or endpoint condition.
- Do not invent evidence, root cause, compromise, or business impact.

Return only valid JSON:
{{
  "overall_posture": "short label such as High - Endpoint Protection Gap",
  "narrative": "maximum 3 short sentences",
  "key_findings": ["maximum 3 concise actionable findings"],
  "recommended_actions": ["maximum 3 prioritized actions"]
}}"""

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior SOC analyst specializing in Sophos Central. "
                    "Return only concise, valid JSON and exclude informational telemetry."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.15,
        "max_tokens": 1000,
        "response_format": {"type": "json_object"},
    }

    try:
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
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = parse_llm_json(content)
        if not parsed:
            log("LLM response was not valid JSON; using rule-based assessment")
            return None
        parsed["key_findings"] = unique_items(parsed.get("key_findings", []), 3)
        parsed["recommended_actions"] = unique_items(
            parsed.get("recommended_actions", []), 3
        )
        parsed["overall_posture"] = str(
            parsed.get("overall_posture") or build_posture_label(stats)
        ).strip()
        parsed["narrative"] = str(
            parsed.get("narrative") or build_rule_based_soc_assessment(stats)["narrative"]
        ).strip()
        return parsed
    except Exception as exc:
        log(f"Error getting Athena-AI assessment: {exc}")
        return None


# -----------------------------------------------------------------------------
# HTML helpers
# -----------------------------------------------------------------------------
def fmt_num(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def risk_color(risk):
    return {
        "Critical": "#991b1b",
        "High": "#dc2626",
        "Medium": "#d97706",
        "Low": "#059669",
    }.get(risk, "#475569")


def metric_card(title, value, color):
    return f"""
    <td style="padding:6px;vertical-align:top;">
      <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;">
        <tr><td style="padding:14px;text-align:center;">
          <div style="font-size:25px;font-weight:700;color:{color};">{html.escape(str(value))}</div>
          <div style="font-size:11px;text-transform:uppercase;color:#64748b;letter-spacing:.4px;margin-top:4px;">{html.escape(title)}</div>
        </td></tr>
      </table>
    </td>"""


def build_dynamic_metric_cards(stats):
    """Show only decision-making metrics; never render zero-value cards."""
    cards = [metric_card("Overall Posture", stats["risk"], risk_color(stats["risk"]))]

    if stats["alerts"]["critical"] > 0:
        cards.append(metric_card("Critical", fmt_num(stats["alerts"]["critical"]), "#991b1b"))
    if stats["alerts"]["high"] > 0:
        cards.append(metric_card("High", fmt_num(stats["alerts"]["high"]), "#dc2626"))
    if stats["endpoints"]["attention_count"] > 0:
        cards.append(
            metric_card(
                "Endpoints Requiring Action",
                fmt_num(stats["endpoints"]["attention_count"]),
                "#d97706",
            )
        )
    if stats["failed_actions"]["total"] > 0:
        cards.append(
            metric_card(
                "Failed Actions",
                fmt_num(stats["failed_actions"]["total"]),
                "#7c2d12",
            )
        )

    width = max(1, min(len(cards), 4))
    cells = []
    for card_html in cards:
        cells.append(card_html.replace('<td style=', f'<td width="{100 // width}%" style=', 1))
    return '<table width="100%" cellpadding="0" cellspacing="0"><tr>' + "".join(cells) + "</tr></table>"


def section(title, body, accent="#0d47a1"):
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;margin:14px 0;">
      <tr><td style="padding:14px 18px;border-left:4px solid {accent};">
        <h3 style="margin:0 0 12px 0;color:#0f172a;font-size:16px;">{html.escape(title)}</h3>
        {body}
      </td></tr>
    </table>"""


def list_html(items, empty_text="No action required."):
    if not items:
        return f"<p style='margin:0;color:#475569;'>{html.escape(empty_text)}</p>"
    return "<ul style='margin:6px 0;padding-left:20px;'>" + "".join(
        f"<li style='margin:5px 0;'>{html.escape(str(item))}</li>" for item in items
    ) + "</ul>"


def build_soc_assessment_html(assessment, risk):
    findings = assessment.get("key_findings", [])[:3]
    actions = assessment.get("recommended_actions", [])[:3]
    posture = assessment.get("overall_posture") or build_posture_label({
        "risk": risk,
        "alerts": {"records": [], "high": 0},
        "endpoints": {"with_threats": 0},
        "failed_actions": {"total": 0},
    })
    narrative = assessment.get("narrative", "")

    findings_html = ""
    if findings:
        findings_html = (
            "<div style='margin-top:14px;font-weight:700;'>Key SOC Findings</div>"
            + "<ul style='margin:6px 0 0 0;padding-left:20px;'>"
            + "".join(
                f"<li style='margin:5px 0;'>{html.escape(str(item))}</li>" for item in findings
            )
            + "</ul>"
        )

    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;margin:12px 0;">
      <tr><td style="padding:15px 18px;color:#1e293b;font-size:14px;line-height:1.5;border-left:4px solid {risk_color(risk)};">
        <div style="font-weight:700;font-size:16px;margin-bottom:9px;">Athena-AI Narrative</div>
        <div style="margin-bottom:10px;">
          <span style="display:inline-block;background:{risk_color(risk)};color:#fff;padding:5px 10px;border-radius:14px;font-size:12px;font-weight:700;">
            Overall Posture: {html.escape(str(posture))}
          </span>
        </div>
        <div>{html.escape(str(narrative))}</div>
        {findings_html}
      </td></tr>
    </table>"""



def build_positive_observations(stats):
    """Return concise, evidence-based positive Sophos observations."""
    observations = []

    if as_int(stats.get("audit_activity", {}).get("total")) > 0:
        observations.append(
            "Sophos response and administrative activity is being captured in the dedicated audit index."
        )

    if as_int(stats.get("outbreaks", {}).get("total")) == 0:
        observations.append(
            "No Sophos outbreak correlation records were identified in the selected reporting period."
        )

    if as_int(stats.get("failed_actions", {}).get("total")) == 0 and as_int(
        stats.get("audit_activity", {}).get("total")
    ) > 0:
        observations.append(
            "No failed or denied Sophos response actions were identified in the selected reporting period."
        )

    return observations[:3]


def build_security_operational_recommendations(stats, assessment):
    """Return only prioritized, non-duplicative Sophos security and operational actions."""
    alerts = stats.get("alerts", {})
    endpoints = stats.get("endpoints", {})
    failures = stats.get("failed_actions", {})
    prioritized = []

    def add(category, text):
        if text and not any(existing_category == category for existing_category, _ in prioritized):
            prioritized.append((category, text))

    records = alerts.get("records", []) or []
    combined_alert_text = " ".join(
        lower(
            " ".join(
                str(record.get(key) or "")
                for key in ("event_type", "alert_type", "description")
            )
        )
        for record in records
    )

    mac_gap = any(
        token in combined_alert_text
        for token in ("machealth", "macos", "prerequisite", "mdm")
    )
    if mac_gap:
        add(
            "mac_remediation",
            "Complete the required Sophos macOS MDM profiles and security permissions on the affected device.",
        )
        add(
            "mac_validation",
            "Revalidate the device in Sophos Central and close the finding only after its protection health returns to healthy/protected.",
        )

    if as_int(endpoints.get("with_threats")) > 0:
        add(
            "threat_response",
            "Triage endpoints reporting threats, run a full Sophos scan, validate containment, and release isolation only after the detection is cleared.",
        )

    if as_int(endpoints.get("stale")) > 0:
        add(
            "connectivity",
            "Restore Sophos agent service and network connectivity on stale endpoints, then confirm a fresh check-in in Sophos Central.",
        )

    attention = endpoints.get("attention", []) or []
    if any("not enrolled" in lower(item.get("attention_reason")) for item in attention):
        add(
            "enrollment",
            "Re-enroll unmanaged endpoints and confirm that the correct Sophos protection policy is assigned.",
        )

    if as_int(failures.get("total")) > 0:
        add(
            "failed_action",
            "Validate the Sophos Management credential for endpoint response actions, confirm endpoint connectivity, and retry failed commands after correcting the reported error.",
        )

    if as_int(stats.get("outbreaks", {}).get("total")) > 0:
        add(
            "outbreak_review",
            "Review the correlated Sophos outbreak activity, identify affected endpoints, and validate containment before closure.",
        )

    # Add only distinct AI recommendations that are not already represented above.
    for item in assessment.get("recommended_actions", []) or []:
        text = str(item).strip()
        value = lower(text)
        if not text:
            continue
        if any(token in value for token in ("macos", "mdm", "prerequisite")):
            category = "mac_remediation"
        elif any(token in value for token in ("healthy", "protected state", "health returns", "revalidate")):
            category = "mac_validation" if mac_gap else "health_validation"
        elif any(token in value for token in ("threat", "scan", "contain", "isolate")):
            category = "threat_response"
        elif any(token in value for token in ("check-in", "connectivity", "service")):
            category = "connectivity"
        elif any(token in value for token in ("enroll", "policy assignment")):
            category = "enrollment"
        elif any(token in value for token in ("credential", "api role", "failed action", "retry")):
            category = "failed_action"
        else:
            category = "ai_" + str(len(prioritized))
        add(category, text)

    if (as_int(alerts.get("critical")) > 0 or as_int(alerts.get("high")) > 0) and not prioritized:
        add(
            "investigation",
            "Investigate the affected endpoint, document containment and remediation evidence, and close the finding only after protection health is restored.",
        )

    return [text for _, text in prioritized[:4]]

def build_security_operational_recommendations_html(stats, assessment):
    positive_observations = build_positive_observations(stats)
    recommendations = build_security_operational_recommendations(stats, assessment)

    positive_items = "".join(
        f"<li style='margin:6px 0;'>{html.escape(str(item))}</li>"
        for item in positive_observations
    ) or "<li style='margin:6px 0;'>No positive operational observation is available for this period.</li>"

    recommendation_items = "".join(
        f"<li style='margin:7px 0;'>{html.escape(str(item))}</li>"
        for item in recommendations
    ) or "<li style='margin:7px 0;'>No priority remediation action is required for this period.</li>"

    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#fff;border:1px solid #cbd5e1;border-radius:8px;margin:12px 0;">
      <tr><td style="padding:15px 18px;color:#1e293b;font-size:14px;line-height:1.5;border-left:4px solid #0f766e;">
        <div style="font-weight:700;font-size:16px;color:#134e4a;margin-bottom:12px;">Sophos Security &amp; Operational Recommendations</div>
        <div style="background:#ecfdf5;border-left:4px solid #059669;padding:11px 13px;border-radius:6px;margin-bottom:12px;">
          <div style="font-weight:700;color:#065f46;margin-bottom:5px;">Positive Observations:</div>
          <ul style="margin:0;padding-left:20px;">{positive_items}</ul>
        </div>
        <div style="background:#fff7ed;border-left:4px solid #d97706;padding:11px 13px;border-radius:6px;">
          <div style="font-weight:700;color:#92400e;margin-bottom:5px;">Prioritized Recommendations:</div>
          <ol style="margin:0;padding-left:20px;">{recommendation_items}</ol>
        </div>
      </td></tr>
    </table>"""

def build_alert_table(records):
    if not records:
        return ""
    rows = []
    for record in records:
        endpoint = record.get("endpoint_name") or record.get("source") or "N/A"
        finding = (
            record.get("description")
            or record.get("event_type")
            or record.get("alert_type")
            or "Sophos finding"
        )
        action = alert_specific_recommendation(record)
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;white-space:nowrap;'>{html.escape(format_timestamp(record.get('created_at')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;font-weight:600;'>{html.escape(str(endpoint))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>{html.escape(str(finding))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>{html.escape(str(action))}</td>"
            "</tr>"
        )
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f1f5f9;">
        <th style="padding:8px;text-align:left;">Time</th>
        <th style="padding:8px;text-align:left;">Endpoint</th>
        <th style="padding:8px;text-align:left;">Finding</th>
        <th style="padding:8px;text-align:left;">Required Action</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>"""


def display_ip_addresses(value):
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value or "N/A")


def endpoint_required_action(endpoint):
    hostname = endpoint.get("hostname") or endpoint.get("sophos_id") or "endpoint"
    reason = endpoint.get("attention_reason", "Requires action")
    if as_int(endpoint.get("threat_count")) > 0:
        return f"Triage {hostname}, run a full scan, and isolate it if compromise is suspected."
    if "Protection health" in reason:
        return f"Restore Sophos protection and confirm the endpoint returns to a healthy state."
    if "No Sophos check-in" in reason:
        return "Check the Sophos service, network access, and endpoint connectivity."
    if "not enrolled" in lower(reason):
        return "Re-enroll the endpoint and confirm its Sophos policy assignment."
    if "isolated" in lower(reason):
        return "Confirm whether containment is still required before releasing the endpoint."
    return "Investigate and close the endpoint protection exception."


def build_endpoint_table(records):
    if not records:
        return ""
    rows = []
    for endpoint in records:
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;font-weight:600;'>{html.escape(str(endpoint.get('hostname') or endpoint.get('sophos_id') or 'N/A'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>{html.escape(str(endpoint.get('attention_reason') or 'Requires action'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>{html.escape(endpoint_required_action(endpoint))}</td>"
            "</tr>"
        )
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f1f5f9;">
        <th style="padding:8px;text-align:left;">Endpoint</th>
        <th style="padding:8px;text-align:left;">Issue</th>
        <th style="padding:8px;text-align:left;">Required Action</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>"""


def build_failed_action_table(records):
    if not records:
        return ""
    rows = []
    for record in records:
        target = record.get("endpoint_id") or record.get("alert_id") or record.get("command_id") or "N/A"
        error = record.get("message") or record.get("status") or "Action failed"
        rows.append(
            "<tr>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;white-space:nowrap;'>{html.escape(format_timestamp(record.get('timestamp')))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;font-weight:600;'>{html.escape(str(record.get('action') or 'N/A'))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>{html.escape(str(target))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>{html.escape(str(error))}</td>"
            f"<td style='padding:8px;border-bottom:1px solid #e2e8f0;'>Validate API role and endpoint connectivity, then retry.</td>"
            "</tr>"
        )
    return f"""
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:12px;">
      <thead><tr style="background:#f1f5f9;">
        <th style="padding:8px;text-align:left;">Time</th>
        <th style="padding:8px;text-align:left;">Action</th>
        <th style="padding:8px;text-align:left;">Target</th>
        <th style="padding:8px;text-align:left;">Error</th>
        <th style="padding:8px;text-align:left;">Required Action</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>"""


def build_html_report(report_type, time_from, time_to, stats, assessment):
    from_date = parse_datetime(time_from).strftime("%B %d, %Y %H:%M UTC")
    to_date = parse_datetime(time_to).strftime("%B %d, %Y %H:%M UTC")

    critical_records = [
        record for record in stats["alerts"]["records"] if severity_rank(record) >= 4
    ]
    high_records = [
        record for record in stats["alerts"]["records"] if severity_rank(record) == 3
    ]

    alerted_endpoints = {
        lower(record.get("endpoint_name") or record.get("source"))
        for record in stats["alerts"]["records"]
        if record.get("endpoint_name") or record.get("source")
    }
    endpoint_records = [
        endpoint
        for endpoint in stats["endpoints"]["attention"]
        if lower(endpoint.get("hostname") or endpoint.get("sophos_id")) not in alerted_endpoints
        or as_int(endpoint.get("threat_count")) > 0
    ]

    actionable_sections = []
    if critical_records:
        actionable_sections.append(
            section("Critical Findings", build_alert_table(critical_records), "#991b1b")
        )
    if high_records:
        actionable_sections.append(
            section("High Findings", build_alert_table(high_records), "#dc2626")
        )
    if endpoint_records:
        actionable_sections.append(
            section("Endpoint Actions", build_endpoint_table(endpoint_records), "#d97706")
        )
    if stats["failed_actions"]["records"]:
        actionable_sections.append(
            section(
                "Failed Sophos Actions",
                build_failed_action_table(stats["failed_actions"]["records"]),
                "#b91c1c",
            )
        )

    if not actionable_sections:
        actionable_sections.append(
            """
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;margin:12px 0;">
              <tr><td style="padding:14px 18px;color:#065f46;font-size:14px;font-weight:600;">
                No Sophos condition requiring SOC action was identified.
              </td></tr>
            </table>
            """
        )

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:Arial,sans-serif;color:#334155;">
  <table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:1000px;background:#f8fafc;">
      <tr><td style="background:#0d47a1;color:#fff;padding:15px 20px;">
        <div style="font-size:19px;font-weight:700;">{html.escape(ATHENA_NAME)} — {html.escape(report_type.title())} Sophos Central Report</div>
        <div style="font-size:12px;margin-top:5px;">Tenant: {html.escape(TENANT_NAME)}</div>
        <div style="font-size:12px;margin-top:4px;">{html.escape(from_date)} — {html.escape(to_date)}</div>
      </td></tr>
      <tr><td style="padding:16px 20px;">
        {build_dynamic_metric_cards(stats)}
        {build_soc_assessment_html(assessment, stats['risk'])}
        {build_security_operational_recommendations_html(stats, assessment)}
        {''.join(actionable_sections)}
      </td></tr>
      <tr><td style="background:#f1f5f9;padding:10px 18px;font-size:11px;color:#64748b;">
        <strong>Athena Security Group</strong> &nbsp;|&nbsp; Report version: {html.escape(REPORT_VERSION)}
      </td></tr>
    </table>
  </td></tr></table>
</body>
</html>"""


def build_plain_report(report_type, time_from, time_to, stats, assessment):
    lines = [
        f"{ATHENA_NAME} - {report_type.upper()} SOPHOS CENTRAL REPORT",
        f"Tenant: {TENANT_NAME}",
        f"Period: {time_from} to {time_to}",
        f"Overall Risk: {stats['risk']}",
        "",
        f"Posture: {assessment.get('overall_posture', stats['risk'])}",
        "",
        "ATHENA-AI NARRATIVE",
        assessment.get("narrative", ""),
    ]

    findings = assessment.get("key_findings", [])[:3]
    if findings:
        lines.extend(["", "KEY SOC FINDINGS"])
        lines.extend(f"- {item}" for item in findings)

    positive_observations = build_positive_observations(stats)
    recommendations = build_security_operational_recommendations(stats, assessment)
    lines.extend(["", "SOPHOS SECURITY & OPERATIONAL RECOMMENDATIONS"])
    lines.append("Positive Observations:")
    if positive_observations:
        lines.extend(f"- {item}" for item in positive_observations)
    else:
        lines.append("- No positive operational observation is available for this period.")
    lines.append("Prioritized Recommendations:")
    if recommendations:
        lines.extend(f"- {item}" for item in recommendations)
    else:
        lines.append("- No priority remediation action is required for this period.")

    critical_records = [
        record for record in stats["alerts"]["records"] if severity_rank(record) >= 4
    ]
    high_records = [
        record for record in stats["alerts"]["records"] if severity_rank(record) == 3
    ]

    for title, records in (("CRITICAL FINDINGS", critical_records), ("HIGH FINDINGS", high_records)):
        if records:
            lines.extend(["", title])
            for record in records:
                lines.append(
                    f"- {format_timestamp(record.get('created_at'))} | "
                    f"{record.get('endpoint_name') or record.get('source') or 'N/A'} | "
                    f"{record.get('description') or record.get('event_type') or record.get('alert_type') or 'Sophos finding'} | "
                    f"Action: {alert_specific_recommendation(record)}"
                )

    alerted_endpoints = {
        lower(record.get("endpoint_name") or record.get("source"))
        for record in stats["alerts"]["records"]
        if record.get("endpoint_name") or record.get("source")
    }
    endpoint_records = [
        endpoint
        for endpoint in stats["endpoints"]["attention"]
        if lower(endpoint.get("hostname") or endpoint.get("sophos_id")) not in alerted_endpoints
        or as_int(endpoint.get("threat_count")) > 0
    ]
    if endpoint_records:
        lines.extend(["", "ENDPOINT ACTIONS"])
        for endpoint in endpoint_records:
            lines.append(
                f"- {endpoint.get('hostname') or endpoint.get('sophos_id') or 'N/A'} | "
                f"{endpoint.get('attention_reason')} | "
                f"Action: {endpoint_required_action(endpoint)}"
            )

    if stats["failed_actions"]["records"]:
        lines.extend(["", "FAILED SOPHOS ACTIONS"])
        for record in stats["failed_actions"]["records"]:
            lines.append(
                f"- {format_timestamp(record.get('timestamp'))} | "
                f"{record.get('action') or 'N/A'} | "
                f"{record.get('message') or record.get('status') or 'Action failed'} | "
                "Action: validate API role and endpoint connectivity, then retry."
            )

    if not critical_records and not high_records and not endpoint_records and not stats["failed_actions"]["records"]:
        lines.extend(["", "No Sophos condition requiring SOC action was identified."])

    lines.extend(["", f"Report version: {REPORT_VERSION}"])
    return "\n".join(lines)


def save_report_files(report_type, time_from, html_body, plain_body):
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    date_label = parse_datetime(time_from).strftime("%Y%m%d")
    base = os.path.join(REPORT_OUTPUT_DIR, f"sophos_{report_type}_{date_label}")
    html_path = f"{base}.html"
    text_path = f"{base}.txt"
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(html_body)
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write(plain_body)
    log(f"Saved Sophos report files: {html_path}, {text_path}")


def send_email(recipients, subject, plain_body, html_body):
    try:
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            raise RuntimeError("SMTP_USERNAME or SMTP_PASSWORD is not configured")

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
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(message)
        server.quit()
        log(f"Sophos Central report sent successfully to {recipients}")
        return True
    except Exception as exc:
        log(f"Error sending Sophos Central report email: {exc}")
        return False


def generate_report(report_type, time_from, time_to, recipients):
    log(
        f"Generating {report_type} Sophos Central report from "
        f"{time_from} to {time_to}"
    )
    stats = collect_stats(time_from, time_to)

    assessment = (
        get_ai_soc_assessment(stats, report_type, time_from, time_to)
        or build_rule_based_soc_assessment(stats)
    )
    log("Athena-AI Insights section prepared for Sophos Central report")

    html_body = build_html_report(report_type, time_from, time_to, stats, assessment)
    plain_body = build_plain_report(report_type, time_from, time_to, stats, assessment)

    date_label = parse_datetime(time_from).strftime("%b %d, %Y")
    subject = (
        f"[{TENANT_NAME}] Athena SOC {report_type.title()} Sophos Central Report "
        f"- {date_label}"
    )

    delivered = False
    if REPORT_SOPHOS_SEND_EMAIL:
        delivered = send_email(recipients, subject, plain_body, html_body)
        if not delivered:
            log("Email delivery failed; saving a local copy of the generated Sophos report")
            save_report_files(report_type, time_from, html_body, plain_body)
    else:
        log("REPORT_SOPHOS_SEND_EMAIL=false; email delivery skipped")

    if REPORT_SOPHOS_SAVE_OUTPUT:
        save_report_files(report_type, time_from, html_body, plain_body)

    # A report is successfully generated even when email is intentionally disabled.
    return delivered or not REPORT_SOPHOS_SEND_EMAIL or REPORT_SOPHOS_SAVE_OUTPUT


def resolve_period(args):
    if len(args) < 2:
        raise ValueError(
            "Usage: reports_sophos.py <daily|weekly|monthly|custom> "
            "[start_time] [end_time]"
        )

    report_type = args[1].lower()
    now = datetime.now(timezone.utc)

    if report_type == "daily":
        time_to = now
        time_from = now - timedelta(days=1)
    elif report_type == "weekly":
        time_to = now
        time_from = now - timedelta(days=7)
    elif report_type == "monthly":
        time_to = now
        time_from = now - timedelta(days=30)
    elif report_type == "custom":
        if len(args) < 4:
            raise ValueError(
                "Custom report requires: reports_sophos.py custom "
                "<start_time> <end_time>"
            )
        # Validate supplied timestamps.
        if not parse_datetime(args[2]) or not parse_datetime(args[3]):
            raise ValueError("Custom start_time and end_time must be valid ISO-8601 timestamps")
        return report_type, args[2], args[3]
    else:
        raise ValueError(f"Unknown report type: {report_type}")

    return (
        report_type,
        time_from.isoformat().replace("+00:00", "Z"),
        time_to.isoformat().replace("+00:00", "Z"),
    )


def main(args):
    if not REPORT_SOPHOS_ENABLED:
        log("REPORT_SOPHOS_ENABLED=false; skipping Sophos report")
        return

    report_type, time_from, time_to = resolve_period(args)
    log(f"Sophos report version: {REPORT_VERSION}")
    log(f"Recipients: {SMTP_RECIPIENT}")
    success = generate_report(
        report_type, time_from, time_to, SMTP_RECIPIENT
    )
    if not success:
        log("Sophos Central report generation or delivery did not complete successfully")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as exc:
        log(f"Unhandled exception: {exc}")
        raise
