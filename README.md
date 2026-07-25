# Sentinel-JVM — Shadow AI Monitoring and Governance Gateway

Sentinel-JVM is a real-time security gateway and data loss prevention (DLP) engine designed to monitor, inspect, score, redact, block, and log unsanctioned "Shadow AI" traffic across enterprise networks.

---

## 🌟 Key Features

- **TLS Interception Layer**: Custom `mitmproxy` addon (`sentinel_addon.py`) intercepting outbound HTTPS traffic to generative AI services (ChatGPT, Claude, Perplexity, OpenAI API, HuggingFace).
- **Inspection Engine**: High-throughput Spring Boot 3.2+ service leveraging **Java 21 Virtual Threads** for non-blocking execution with `< 15ms` added latency per request.
- **DLP Secret Detection**:
  - **CRITICAL**: Live AWS AKIA access keys, RSA/EC PEM private key blocks, GCP Service Account JSONs -> Triggers instant **BLOCK** (returns HTTP 403 Forbidden before reaching AI destination).
  - **REDACTABLE**: Password fields, Bearer tokens, API keys, JWTs, Credit Card numbers (with Luhn validation) -> Sanitizes payload in place keeping JSON structure intact.
- **ML Anomaly Detection**: Separate Python FastAPI microservice wrapping a scikit-learn **IsolationForest** model trained on synthetic normal vs anomalous traffic features (payload size, off-hours execution, burst frequency, user risk).
- **Reactive Persistence**: Real-time audit trail stored in MongoDB 6.0+ via **Spring Data Reactive MongoDB**.
- **Real-Time Security Alerting**: Automatic alert dispatching for `HIGH` and `CRITICAL` risk events via webhooks and email notifications.
- **Governance Dashboard**: Responsive Vite + React frontend featuring live event feeds, risk tier distribution donut charts, time-series usage trends, and payload redaction detail modals.

---

## 🚀 Quick Start (Docker Compose)

Run the entire system with one single command:

```bash
docker-compose up --build
```

### Services & Ports:

| Service | Technology | Port | Description |
| :--- | :--- | :--- | :--- |
| **Governance Dashboard** | Vite + React | `http://localhost:3000` | Real-time monitoring & audit table |
| **Inspection Gateway** | Java 21 Spring Boot | `http://localhost:8080` | Core DLP & Risk Evaluation REST API |
| **ML Anomaly Service** | FastAPI + scikit-learn | `http://localhost:5000` | IsolationForest anomaly score API |
| **TLS Proxy** | mitmproxy | `http://localhost:8082` | Interception Forward Proxy |
| **Audit Database** | MongoDB 6.0 | `mongodb://localhost:27017` | Persistent audit trail store |

---

## 🧪 Simulation & Testing

Run the included test simulation script against the inspection gateway:

```bash
python demo/run_simulation.py
```

### Example Simulation Output:

```text
================================================================================
  SENTINEL-JVM: SHADOW AI MONITORING & GOVERNANCE GATEWAY SIMULATION
================================================================================

---> Running Test: 1. Standard Compliant AI Prompt (Clean)
  [RESULT] Action: ALLOW | Risk Tier: LOW | Inspection Time: 4.8ms
  Status: PASSED [Matches expected policy decision]

---> Running Test: 2. Sensitive Developer Request with Password & Bearer Token
  [RESULT] Action: REDACT | Risk Tier: HIGH | Inspection Time: 8.2ms
  [SECRETS] Matched Patterns: PASSWORD_FIELD, BEARER_TOKEN
  [REDACTED PAYLOAD SAMPLE] {"dbUser": "admin", "password": "[REDACTED_PASSWORD]", "authHeader": "Bearer [REDACTED_BEARER_TOKEN]"}
  Status: PASSED [Matches expected policy decision]

---> Running Test: 3. Unsanctioned Data Exfiltration with AWS Secret Key
  [RESULT] Action: BLOCK | Risk Tier: CRITICAL | Inspection Time: 6.1ms
  [SECRETS] Matched Patterns: AWS_ACCESS_KEY
  [BLOCK REASON] Live AWS Cloud credentials (AKIA-prefixed key) detected in payload
  Status: PASSED [Matches expected policy decision]
```

---

## 🔒 Certificate Setup for Browser Interception (mitmproxy CA)

To route local browser traffic through the gateway:
1. Start mitmproxy (`mitmdump -s mitmproxy-addon/sentinel_addon.py`).
2. Configure browser proxy settings to `http://127.0.0.1:8080` (or `8082` in Docker).
3. Navigate to `http://mitm.it` in your browser to download and install the generated mitmproxy Root CA certificate into your Trusted Root Certification Authorities store.
