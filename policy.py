"""Prototype policy gateway and conservative, exact-match provenance helpers."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlparse
from typing import Any

INTERNAL_EMAIL_DOMAINS = {"acme.example.test"}
ALLOWED_HTTP_HOSTS = {"support.example.test", "status.example.test"}
TRUST_BY_TIER = {1: "trusted", 2: "internal", 3: "untrusted"}
DEMO_CUSTOMER_IDS = {"C-104", "C-208", "C-319"}


def _signals(text: str) -> set[str]:
    """Return identifiers/entities useful for exact source matching."""
    patterns = [
        r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        r"\b[A-Z]{1,8}-\d{2,}\b",
    ]
    found = {match.group(0).lower() for pattern in patterns for match in re.finditer(pattern, text, re.I)}
    # Hostnames derived from an untrusted email destination remain attributable to that email.
    found.update(match.group(0).lower().rsplit("@", 1)[-1] for match in re.finditer(patterns[0], text, re.I))
    found.update(match.group(0).lower() for match in re.finditer(r"\b(?:wiki|ticket|email)-\d+\b", text, re.I))
    return found


def provenance_for(value: Any, query: str, docs: list[dict[str, Any]], tool_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Trace exact identifiers and phrases. Unknown/paraphrased text stays explicitly unresolved."""
    text = str(value or "").strip()
    if not text:
        return [{"source_type": "empty", "label": "empty value", "confidence": "exact"}]
    lowered = text.lower()
    matches: list[dict[str, Any]] = []

    known_customer_entities: set[str] = set()
    for result in tool_results:
        content = result.get("content", "")
        if result.get("source_id") == "customers" and isinstance(content, list):
            for row in content:
                if isinstance(row, dict):
                    known_customer_entities.update(str(row.get(field, "")).lower() for field in ("customer_id", "name", "email") if row.get(field))
    query_signals = _signals(query) | {entity for entity in known_customer_entities if entity in query.lower()}
    if lowered in query.lower() or any(signal in lowered for signal in query_signals):
        matches.append({"source_type": "user_request", "label": "User request", "confidence": "exact entity match"})

    for doc in docs:
        doc_text = f"{doc.get('doc_id', '')} {doc.get('title', '')} {doc.get('text', '')}"
        signals = _signals(doc_text)
        matched = [signal for signal in signals | known_customer_entities if signal in lowered]
        if lowered in doc_text.lower() and len(lowered) >= 8:
            matched.append(text)
        if matched:
            tier = int(doc.get("tier", 0))
            matches.append({
                "source_type": "document",
                "source_id": doc.get("doc_id"),
                "label": doc.get("title", doc.get("doc_id", "Retrieved document")),
                "tier": tier,
                "trust": TRUST_BY_TIER.get(tier, "unknown"),
                "matched_values": sorted(set(matched)),
                "confidence": "exact entity/phrase match",
            })

    for result in tool_results:
        content = result.get("content", "")
        content_text = json_safe_text(content)
        result_signals = _signals(content_text)
        if result.get("source_id") == "customers" and isinstance(content, list):
            result_signals |= {str(row.get(field, "")).lower() for row in content if isinstance(row, dict) for field in ("customer_id", "name", "email") if row.get(field)}
        matched = [signal for signal in result_signals if signal in lowered]
        if lowered in content_text.lower() and len(lowered) >= 8:
            matched.append(text)
        if matched:
            source_match = {
                "source_type": "tool_result",
                "source_id": result.get("source_id", result.get("tool")),
                "label": result.get("source_label", result.get("tool", "Tool result")),
                "matched_values": sorted(set(matched)),
                "confidence": "exact entity/phrase match",
            }
            if result.get("classification"):
                source_match["classification"] = result["classification"]
            matches.append(source_match)

    if not matches:
        matches.append({
            "source_type": "unresolved",
            "label": "No exact source match; origin unresolved",
            "confidence": "unresolved",
        })
    return matches


def json_safe_text(value: Any) -> str:
    import json
    return json.dumps(value, ensure_ascii=False, default=str) if not isinstance(value, str) else value


def trace_arguments(args: dict[str, Any], query: str, docs: list[dict[str, Any]], tool_results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    traces: dict[str, list[dict[str, Any]]] = {}

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                visit(nested, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                visit(nested, f"{path}[{index}]")
        elif isinstance(value, (str, int, float)):
            traces[path or "value"] = provenance_for(value, query, docs, tool_results)

    visit(args, "")
    return traces


def contains_customer_data(value: Any, tool_results: list[dict[str, Any]], customer_catalog: list[dict[str, Any]]) -> bool:
    text = unquote(json_safe_text(value)).lower()
    customer_markers: set[str] = set()
    # The policy can recognize protected values even if the agent has not successfully read them.
    for row in customer_catalog:
        customer_markers.update(str(row.get(field, "")).lower() for field in ("customer_id", "name", "email") if row.get(field))
    for result in tool_results:
        if result.get("source_id") == "customers":
            content = result.get("content", [])
            if isinstance(content, list):
                for row in content:
                    if isinstance(row, dict):
                        customer_markers.update(str(row.get(field, "")).lower() for field in ("customer_id", "name", "email") if row.get(field))
    return any(marker in text for marker in customer_markers)


def authorize_tool_action(
    tool: str,
    args: dict[str, Any],
    query: str,
    docs: list[dict[str, Any]],
    tool_results: list[dict[str, Any]],
    enabled: bool,
    customer_catalog: list[dict[str, Any]],
) -> tuple[str, str, dict[str, list[dict[str, Any]]]]:
    """Single gateway: every proposed function reaches this policy before execution."""
    origins = trace_arguments(args, query, docs, tool_results)

    # The tool allowlist and basic argument validation are always enforced, even in bypass mode.
    allowed_tools = {"search_docs", "query_db", "db_write", "http_request", "send_email"}
    if tool not in allowed_tools:
        return "BLOCK", "Tool is not on the application's allowlist.", origins
    if not isinstance(args, dict):
        return "BLOCK", "Tool arguments must be a JSON object.", origins

    required = {
        "search_docs": ("query",),
        "query_db": ("table",),
        "db_write": ("table", "customer_id", "status"),
        "http_request": ("method", "url"),
        "send_email": ("to", "subject", "body"),
    }[tool]
    missing = [key for key in required if key not in args]
    if missing:
        return "BLOCK", f"Missing required argument(s): {', '.join(missing)}.", origins
    if any(not isinstance(args[key], str) for key in required):
        return "BLOCK", "All required tool arguments must be strings.", origins
    optional_strings = {"query_db": ("customer_id",), "http_request": ("body",)}.get(tool, ())
    if any(key in args and not isinstance(args[key], str) for key in optional_strings):
        return "BLOCK", "Optional tool arguments must be strings when provided.", origins
    if tool in {"query_db", "db_write"} and args.get("table") != "customers":
        return "BLOCK", "Only the fictional customers table exists in this prototype.", origins
    if tool == "http_request" and str(args.get("method", "")).upper() not in {"GET", "POST"}:
        return "BLOCK", "HTTP method is outside the prototype's GET/POST tool schema.", origins

    if not enabled:
        return "ALLOW", "Security guard is off; the action is marked simulated and will not affect real systems.", origins

    if tool == "search_docs":
        if not str(args.get("query", "")).strip() or len(str(args.get("query", ""))) > 500:
            return "BLOCK", "Document search requires a non-empty query of at most 500 characters.", origins
        return "ALLOW", "Read-only search is limited to the local seeded document collection.", origins

    if tool == "query_db":
        if args.get("table") != "customers":
            return "BLOCK", "Only the local fictional customers table is allow-listed for reading.", origins
        customer_id = str(args.get("customer_id", "")).strip()
        if not customer_id:
            return "BLOCK", "Bulk customer-table reads are denied. Request one specific customer record; only non-contact fields will be returned.", origins
        if customer_id not in DEMO_CUSTOMER_IDS:
            return "BLOCK", "The requested customer ID does not exist in the fictional demo table.", origins
        return "ALLOW", "Single-record read allowed; only customer ID, issue, and status are returned. Contact details are withheld.", origins

    if tool == "db_write":
        return "BLOCK", "Database writes are denied by default; this prototype has no human-approval workflow.", origins

    if tool == "http_request":
        method = str(args.get("method", "")).upper()
        try:
            parsed = urlparse(str(args.get("url", "")))
            host = (parsed.hostname or "").lower()
        except ValueError:
            return "BLOCK", "HTTP URL is malformed.", origins
        if method != "GET":
            return "BLOCK", "Only GET requests are allowed; POST/PUT/PATCH/DELETE can create external side effects.", origins
        if parsed.scheme != "https" or host not in ALLOWED_HTTP_HOSTS or parsed.netloc.lower() not in {host, f"{host}:443"} or parsed.fragment:
            return "BLOCK", f"HTTP destination is not allow-listed ({host or 'invalid host'}).", origins
        if args.get("body"):
            return "BLOCK", "GET requests may not carry a body or customer data.", origins
        if contains_customer_data(args.get("url", ""), tool_results, customer_catalog):
            return "BLOCK", "Customer data may not be sent in an HTTP URL.", origins
        return "ALLOW", f"Read-only HTTPS request to the allow-listed host {host}; request is simulated.", origins

    if tool == "send_email":
        recipient = str(args.get("to", ""))
        domain = recipient.rsplit("@", 1)[-1].lower() if "@" in recipient else ""
        recipient_sources = origins.get("to", [])
        untrusted_recipient = any(source.get("trust") == "untrusted" for source in recipient_sources)
        if untrusted_recipient:
            return "BLOCK", "The recipient came from an untrusted retrieved document; untrusted content cannot choose an email destination.", origins
        if domain not in INTERNAL_EMAIL_DOMAINS:
            return "BLOCK", "Email is allowed only to the demo's explicitly allow-listed internal domain (acme.example.test).", origins
        if contains_customer_data(args.get("body", ""), tool_results, customer_catalog):
            return "BLOCK", "Customer data cannot be emailed by this prototype, even to an internal recipient.", origins
        return "ALLOW", "Recipient is internal and the message contains no detected customer data; email remains simulated.", origins

    return "BLOCK", "No policy exists for this tool.", origins
