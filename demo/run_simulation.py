import time
import json
import requests
import sys

GATEWAY_URL = "http://localhost:8080/api/inspect"

TEST_CASES = [
    {
        "name": "1. Standard Compliant AI Prompt (Clean)",
        "payload": {
            "destinationHost": "chatgpt.com",
            "requestPath": "/v1/chat/completions",
            "method": "POST",
            "clientIp": "192.168.1.104",
            "userId": "alice_engineer",
            "body": json.dumps({
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "How do I implement non-blocking I/O with Java 21 virtual threads?"}]
            })
        },
        "expected_action": "ALLOW",
        "expected_risk": "LOW"
    },
    {
        "name": "2. Sensitive Developer Request with Password & Bearer Token (Redactable Secrets)",
        "payload": {
            "destinationHost": "api.openai.com",
            "requestPath": "/v1/chat/completions",
            "method": "POST",
            "clientIp": "192.168.1.108",
            "userId": "bob_analyst",
            "body": json.dumps({
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "Please debug my app config: {\"dbUser\": \"admin\", \"password\": \"SuperSecretP@ss2026!\", \"authHeader\": \"Bearer eyJhbGciOiJIUzI1NiJ9\"}"}]
            })
        },
        "expected_action": "REDACT",
        "expected_risk": "HIGH"
    },
    {
        "name": "3. Unsanctioned Data Exfiltration with AWS Secret Key (Critical Secret)",
        "payload": {
            "destinationHost": "claude.ai",
            "requestPath": "/api/v1/messages",
            "method": "POST",
            "clientIp": "192.168.1.155",
            "userId": "unknown_contractor",
            "body": json.dumps({
                "model": "claude-3-5-sonnet",
                "messages": [{"role": "user", "content": "Production deployment credentials: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE. Check if permissions are sufficient."}]
            })
        },
        "expected_action": "BLOCK",
        "expected_risk": "CRITICAL"
    },
    {
        "name": "4. PEM Private Key Exfiltration Attempt",
        "payload": {
            "destinationHost": "api.perplexity.ai",
            "requestPath": "/chat/completions",
            "method": "POST",
            "clientIp": "192.168.1.199",
            "userId": "malicious_insider",
            "body": json.dumps({
                "prompt": "Inspect this RSA key block:\n-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3\n-----END PRIVATE KEY-----"
            })
        },
        "expected_action": "BLOCK",
        "expected_risk": "CRITICAL"
    }
]

def run_simulation():
    print("=" * 80)
    print("  SENTINEL-JVM: SHADOW AI MONITORING & GOVERNANCE GATEWAY SIMULATION")
    print("=" * 80)
    print(f"Targeting Inspection Gateway Endpoint: {GATEWAY_URL}\n")

    passed = 0
    total = len(TEST_CASES)

    for tc in TEST_CASES:
        print(f"\n---> Running Test: {tc['name']}")
        payload = tc["payload"]

        try:
            start_time = time.time()
            res = requests.post(GATEWAY_URL, json=payload, timeout=5)
            elapsed_ms = round((time.time() - start_time) * 1000, 2)

            if res.status_code == 200:
                data = res.json()
                action = data.get("decision")
                risk = data.get("riskTier")
                patterns = data.get("detectedPatterns", [])
                latency = data.get("executionTimeMs", elapsed_ms)
                redacted_body = data.get("redactedBody")

                print(f"  [RESULT] Action: {action} | Risk Tier: {risk} | Inspection Time: {latency}ms")
                if patterns:
                    print(f"  [SECRETS] Matched Patterns: {', '.join(patterns)}")
                if action == "BLOCK":
                    print(f"  [BLOCK REASON] {data.get('blockReason')}")
                if action == "REDACT" and redacted_body:
                    print(f"  [REDACTED PAYLOAD SAMPLE] {redacted_body[:120]}...")

                if action == tc["expected_action"]:
                    print("  Status: PASSED [Matches expected policy decision]")
                    passed += 1
                else:
                    print(f"  Status: WARNING [Expected {tc['expected_action']}, got {action}]")
            else:
                print(f"  [ERROR] HTTP {res.status_code}: {res.text}")

        except Exception as e:
            print(f"  [FAIL] Could not connect to gateway: {e}")

    print("\n" + "=" * 80)
    print(f"SIMULATION SUMMARY: {passed}/{total} Test Scenarios Passed Successfully!")
    print("=" * 80)

if __name__ == "__main__":
    run_simulation()
