# 🎤 Sentinel-JVM: In-Depth Technical Presentation & Walkthrough Script

> **Purpose**: Use this script for project presentations, technical interviews, demo recordings, or team walkthroughs. It includes exact spoken lines, visual actions, technical deep-dives, live demo steps, and answers to hard technical questions.

---

## 🎬 Act 1: The Hook & Problem Statement (1.5 Minutes)

### 🗣️ Spoken Script:
> *"Hello everyone! Today, I am excited to present **Sentinel-JVM** — an enterprise-grade, real-time **Shadow AI Monitoring & Data Loss Prevention (DLP) Gateway** built with Java 21, Python FastAPI, and React."*
>
> *"Here is the critical security challenge we are solving today:*
> *As enterprises rapidly adopt Generative AI tools like ChatGPT, Claude, and Perplexity, employees are copy-pasting code snippets, SQL schemas, and server configs into AI prompt boxes."*
>
> *"Without governance, employees unknowingly leak **AWS Secret Keys**, **PEM Private Keys**, **Database Passwords**, **API Tokens**, and **Credit Card Numbers** directly to public AI servers. This creates massive regulatory compliance violations under GDPR, HIPAA, and PCI-DSS."*
>
> *"Traditional corporate firewalls fail here because AI traffic is encrypted over HTTPS, and traditional proxies are either too slow or break modern web applications. **Sentinel-JVM** solves this by performing sub-10ms inline proxy interception, real-time secret redaction, ML anomaly detection, and instant policy enforcement."*

---

## 🏗️ Act 2: High-Level Architecture & Tech Stack (2 Minutes)

### 🗣️ Spoken Script:
> *"Let's take a look at the architecture. Sentinel-JVM is designed as a high-concurrency microservices stack consisting of 4 core decoupled layers:"*

```text
  [ Client PC / Browser ]
           │
           ▼ (HTTPS Port 8082)
 ┌──────────────────────────────────────────────────────────┐
 │ 1. mitmproxy Interceptor Addon (Python)                  │
 └─────────┬────────────────────────────────────────────────┘
           │ (REST POST /api/inspect)
           ▼ (Port 8080)
 ┌──────────────────────────────────────────────────────────┐
 │ 2. Spring Boot 3.2 Gateway (Java 21 Virtual Threads)     │
 │    ├── SecretDetectorService (Regex + Luhn Validation)  │
 │    └── RiskEvaluatorService (Policy Engine)              │
 └─────────┬───────────────────────────────┬────────────────┘
           │ (POST /score)                 │ (Async Persistence)
           ▼ (Port 5000)                   ▼
 ┌──────────────────────────┐   ┌───────────────────────────┐
 │ 3. ML Anomaly Service    │   │ 4. MongoDB Atlas          │
 │    (FastAPI / Scikit)    │   │    (Cloud Persistence)    │
 └──────────────────────────┘   └─────────────┬─────────────┘
                                              │ (REST API)
                                              ▼ (Port 3000)
                                ┌───────────────────────────┐
                                │ 5. SOC Governance UI      │
                                │    (React 18 + Tailwind)  │
                                └───────────────────────────┘
```

> *"1. **Interception Layer (`mitmproxy`)**: A lightweight proxy listening on port 8082. It intercepts outbound HTTPS requests to AI hosts like `chatgpt.com` and `claude.ai`. To maximize speed, static `GET` requests and background browser telemetry pass through instantly with **zero latency**."*
>
> *"2. **Inspection Gateway (`Java 21 / Spring Boot 3.2`)**: Running on Virtual Threads (`Project Loom`), our gateway inspects payloads in parallel with sub-10ms execution overhead. It runs heuristic secret regex checks and Luhn algorithm validation for credit cards."*
>
> *"3. **Machine Learning Anomaly Service (`FastAPI / IsolationForest`)**: A Python microservice that evaluates contextual metrics like payload size, hour of day, and burst frequency using an `IsolationForest` model to detect abnormal exfiltration patterns."*
>
> *"4. **SOC Governance Dashboard (`React 18 / Tailwind CSS`)**: A Datadog-styled real-time dashboard on port 3000 providing live audit logging, telemetry trends, risk donut charts, and side-by-side payload inspection modals."*

---

## 🖥️ Act 3: Live System Demo Walkthrough (3 Minutes)

### 📌 Step 1: Launch the Full System Stack
**Visual Action**: Open VS Code terminal and execute:
```bash
python run_stack.py
```
**Spoken Script**:
> *"With one command, our unified stack launcher boots up all 4 microservices simultaneously. Notice how Spring Boot initializes Tomcat on port 8080 with Java 21 Virtual Threads enabled, FastAPI starts on port 5000, mitmproxy binds to port 8082, and Vite starts our React Dashboard on port 3000."*

---

### 📌 Step 2: Open the SOC Governance Dashboard
**Visual Action**: Open browser to `http://localhost:3000`.
**Spoken Script**:
> *"Here is our Security Operations Center dashboard. At the top, you can see live KPI metric cards for total requests, allowed, redacted, and blocked counts, alongside our average inspection latency of under 8 milliseconds."*
>
> *"Below that are our live visual charts — an hourly interception volume trend chart and a risk distribution donut chart."*

---

### 📌 Step 3: Trigger Live Policy Enforcement Tests
**Visual Action**: Click the header simulation buttons or run `python demo/run_simulation.py` in terminal.

#### 🟢 Scenario 1: Clean AI Prompt (`ALLOW`)
- **Action**: Click **Clean** button in header.
- **Spoken Script**:
  > *"First, an employee submits a clean prompt: 'How do I implement non-blocking I/O in Java 21?'"*
  > *"The gateway verifies no sensitive data is present. Decision: **ALLOW**. Latency added: **4 ms**."*

#### 🟡 Scenario 2: Redactable Secrets (`REDACT`)
- **Action**: Click **Secret** button in header.
- **Spoken Script**:
  > *"Next, a developer copy-pastes a config containing a database password and Bearer token: `dbPassword=SuperSecret123!`."*
  > *"Sentinel-JVM detects the sensitive fields, masks them in-flight as `[REDACTED_PASSWORD]` and `[REDACTED_BEARER_TOKEN]`, and forwards the sanitized payload to OpenAI. The AI answers safely without ever receiving the corporate password!"*

#### 🔴 Scenario 3: Critical Cloud Credential Exfiltration (`BLOCK`)
- **Action**: Click **AWS Block** button in header.
- **Spoken Script**:
  > *"Now, an employee attempts to send a prompt containing a live AWS Access Key (`AKIA1234567890ABCDEF`)."*
  > *"Sentinel-JVM triggers a **CRITICAL** risk alert, immediately aborts the connection, and returns an **HTTP 403 Access Blocked** error response to the user. The AWS key never reaches the public cloud!"*

---

### 📌 Step 4: Side-by-Side Payload Inspector Modal
**Visual Action**: In the Audit Stream Log table, click the **Inspect (👁️)** icon on the top row.
**Spoken Script**:
> *"When a SOC analyst clicks on any audit record, our Event Inspector modal opens. It displays the destination host, risk tier, matched secret signatures, and a side-by-side view comparing the **Captured Raw Payload** with the **Sanitized Payload Forwarded to AI**."*

---

## 🔬 Act 4: Key Engineering Deep Dives (2 Minutes)

### 🗣️ Spoken Script:

#### 1. How did we achieve sub-10ms latency with Java 21?
> *"By enabling Java 21 Virtual Threads (`spring.threads.virtual.enabled=true`), every inspection request executes on a lightweight virtual thread. Virtual threads allow thousands of concurrent non-blocking I/O calls to MongoDB and the ML service without pinning OS kernel threads."*

#### 2. How did we prevent HTTP/2 protocol errors on ChatGPT?
> *"Modern AI sites like ChatGPT strictly enforce the HTTP/2 specification. Custom HTTP headers must be strictly lowercased (`x-sentinel-action` instead of `X-Sentinel-Action`). Also, by bypassing static `GET` asset requests and background telemetry pings (`/rum`, `/ces/`), we eliminated 502 Bad Gateway errors completely."*

#### 3. How did we eliminate recursive proxy loops in Python?
> *"When `mitmproxy` calls `http://localhost:8080/api/inspect`, Python's `requests` library normally inherits the OS `HTTP_PROXY` environment variable, causing the gateway request to proxy back into mitmproxy infinitely. We fixed this by setting `session.trust_env = False` for all internal gateway calls."*

#### 4. How does Luhn Credit Card Validation work?
> *"Instead of relying purely on regex — which causes false positives on long numbers — `SecretDetectorService` validates 13-to-19 digit card numbers using the mathematical **Luhn Check algorithm** before redacting. Only genuine financial credit card numbers trigger redaction."*

---

## ❓ Act 5: Technical Q&A Preparation

| Question | Expert Spoken Answer |
| :--- | :--- |
| **Q: Can Sentinel-JVM monitor other PCs on the same Wi-Fi network?** | *"Yes! You set `mitmdump` to listen on host `0.0.0.0:8082` and configure the target PC's network proxy to your Host PC's LAN IP address (e.g. `192.168.1.50:8082`). Once the root CA certificate is trusted on the target PC, all AI traffic from that PC is governed live on your dashboard."* |
| **Q: What happens if the ML Service goes down?** | *"Sentinel-JVM implements graceful fallback. If the Python ML service is unreachable, `AnomalyClientService` catches the exception via Reactive `onErrorReturn` and assigns a baseline score of `0.05`, ensuring secret detection and proxy traffic continue without interruption."* |
| **Q: How does Sentinel-JVM handle high concurrency?** | *"Spring Boot 3.2 running on Virtual Threads handles thousands of concurrent connections with minimal memory overhead. Coupled with Spring Data Reactive MongoDB, I/O operations never block worker threads."* |

---

## 🏁 Conclusion

> *"To summarize: **Sentinel-JVM** provides enterprise CISOs and SOC teams with a complete, low-latency, real-time solution to monitor, govern, and secure Shadow AI usage across the enterprise. Thank you!"*
