import os
import json
import time
import logging
import requests
from mitmproxy import http

# Configure logging
logging.basicConfig(level=logging.INFO, format="[Sentinel-Addon] %(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sentinel_addon")

GATEWAY_URL = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8080/api/inspect")
MONITORED_DOMAINS = [
    "api.openai.com",
    "chatgpt.com",
    "api.anthropic.com",
    "claude.ai",
    "api.perplexity.ai",
    "huggingface.co",
    "localhost",
    "127.0.0.1"
]

class SentinelMitmAddon:
    def __init__(self):
        logger.info(f"Initialized Sentinel-JVM Mitmproxy Addon. Target Gateway: {GATEWAY_URL}")

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host.lower()

        # 1. Host check
        is_target_host = any(domain in host for domain in MONITORED_DOMAINS)
        if not is_target_host:
            return

        # 2. Method check - ONLY inspect data payload submissions (POST/PUT/PATCH), pass GET requests instantly
        if flow.request.method not in ["POST", "PUT", "PATCH"]:
            return

        # Skip inspection requests targeting gateway itself
        if "api/inspect" in flow.request.path or "8080" in str(flow.request.port):
            return

        body_content = flow.request.text or ""

        # Ignore empty payloads
        if not body_content.strip():
            return

        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "127.0.0.1"

        payload = {
            "destinationHost": host,
            "requestPath": flow.request.path,
            "method": flow.request.method,
            "clientIp": client_ip,
            "userId": flow.request.headers.get("X-User-Id", "employee_user"),
            "body": body_content,
            "timestamp": int(time.time() * 1000)
        }

        start_time = time.time()

        try:
            # Bypass system proxy settings for local inspection gateway call
            session = requests.Session()
            session.trust_env = False
            response = session.post(GATEWAY_URL, json=payload, timeout=2.5)
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            if response.status_code == 200:
                result = response.json()
                decision = result.get("decision", "ALLOW")
                risk_tier = result.get("riskTier", "LOW")
                block_reason = result.get("blockReason", "Policy Violation")
                redacted_body = result.get("redactedBody")

                logger.info(f"[{host}] Decision: {decision} | Risk Tier: {risk_tier} | Latency: {elapsed_ms}ms")

                # Add inspection metadata headers (lowercased for HTTP/2 compliance)
                flow.request.headers["x-sentinel-inspected"] = "true"
                flow.request.headers["x-sentinel-latency-ms"] = str(elapsed_ms)
                flow.request.headers["x-sentinel-risk-tier"] = risk_tier

                if decision == "BLOCK":
                    logger.warning(f"BLOCKED request to {host}. Reason: {block_reason}")
                    error_payload = {
                        "error": "Access Blocked by Sentinel Security Gateway",
                        "status": 403,
                        "riskTier": risk_tier,
                        "reason": block_reason,
                        "destination": host,
                        "timestamp": int(time.time() * 1000)
                    }
                    flow.response = http.Response.make(
                        403,
                        json.dumps(error_payload, indent=2),
                        {
                            "content-type": "application/json",
                            "x-sentinel-action": "BLOCKED"
                        }
                    )
                elif decision == "REDACT" and redacted_body:
                    logger.info(f"REDACTED payload for request to {host}")
                    flow.request.text = redacted_body
                    flow.request.headers["x-sentinel-action"] = "REDACTED"
                else:
                    flow.request.headers["x-sentinel-action"] = "ALLOWED"

            else:
                logger.error(f"Gateway returned non-200 status code: {response.status_code}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Error contacting Sentinel Inspection Gateway at {GATEWAY_URL}: {e}")

addons = [
    SentinelMitmAddon()
]
