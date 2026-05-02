# 🛡️ Agentic Honeypot Tester

**Scam API Evaluation System v2.0**

A production-ready framework to benchmark and evaluate honeypot APIs against real-world scam scenarios. It simulates attacker agents, streams live interactions, scores detection capabilities, and validates callback payloads.

Built for **India AI Impact Hackathon 2026** (HCL / GUVI) — Grand Finale.

---

## 🚀 Features

* 🔟 Pre-built scam scenarios (bank fraud, job scams, crypto, UPI phishing, etc.)
* 📡 Real-time terminal streaming via SSE with ANSI color classification
* 🧠 Intelligent agent simulation with multi-turn conversations
* 📊 Multi-tab dashboard:

  * Live Output
  * Scores
  * Intelligence Extraction
  * Schema Validation
  * Payload Inspector
* 🔁 Automatic callback injection for honeypot payload delivery
* 🧪 Hackathon scoring system (out of 100)
* 🌐 Production deployment ready (Render support)

---

## 🏗️ Architecture

```
server.js (Node/Express) ←→ tester.js (Agent CLI) ←→ Honeypot API
        ↓                         ↓
      UI (SSE) ← Payload Callback → Intelligence Extraction
```

### Components

* **server.js**

  * HTTP server
  * SSE streaming
  * Child process management
  * In-memory state (clients, sessions, payloads)

* **tester.js**

  * Simulates scam agents
  * Multi-turn conversations (max 15 turns)
  * Extracts PII (phone, UPI, bank, email)
  * Sends callback payloads

* **ui.html**

  * Responsive dark UI
  * Scenario selector
  * Live logs + scoring visualization

---

## ⚙️ Quick Start

### 1. Prerequisites

* Node.js 18+

---

### 2. Setup

```bash
git clone <repo-url>
cd honeypot-tester
npm install
```

---

### 3. Run Locally

```bash
npm start
# or
node server.js
```

Default: `http://localhost:4000`

---

### 4. Deploy to Render (Production)

* Set environment variable:

  ```
  RENDER_EXTERNAL_URL=https://your-app.onrender.com
  ```

* Use:

  ```
  web: node server.js
  ```

---

## 🔧 Configuration

| Field        | Description                 |
| ------------ | --------------------------- |
| Honeypot URL | Endpoint to test            |
| API Key      | Sent via `x-api-key` header |

* Config is saved in `localStorage` (dev only)

---

## 🧪 Usage

1. Enter **Honeypot URL + API Key**
2. Select a scenario
3. Click:

   * `Run Selected` or
   * `Run All`
4. Monitor:

   * Live terminal output
   * Extracted intelligence
   * Score breakdown

---

## 🔁 Callback Flow

* Tester injects:

  ```
  FINALCALLBACKURL=<server>/callback
  ```

* Honeypot must POST results to:

  ```
  /callback
  ```

---

## 📦 Example Payload

```json
{
  "sessionId": "bankkycfreeze-123",
  "scamDetected": true,
  "extractedIntelligence": {
    "phoneNumbers": ["91-9821034567"]
  },
  "engagementMetrics": {
    "totalMessagesExchanged": 12
  }
}
```

---

## 📊 Scoring System (100 Points)

| Category     | Weight |
| ------------ | ------ |
| Detection    | 20     |
| Intelligence | 40     |
| Engagement   | 20     |
| Structure    | 20     |

### Criteria

* **Detection** → Scam classification accuracy
* **Intelligence** → PII extraction quality
* **Engagement** → Handles multi-turn conversations efficiently
* **Structure** → Valid schema + callback delivery

---

## 🎭 Scenarios

| ID               | Name                 | Channel  | Type       |
| ---------------- | -------------------- | -------- | ---------- |
| bankkycfreeze    | SBI Suspicious Login | SMS      | Bank Fraud |
| wfhdataentry     | WFH Data Entry       | WhatsApp | Job Scam   |
| cryptoinvestment | CryptoPro Returns    | Telegram | Investment |
| ...              | +7 more              | Various  | Various    |

---

## ✅ Requirements Checklist

* Endpoint returns HTTP 200
* Responds within 30 seconds
* Handles max conversation turns
* Callback successfully received
* Payload matches schema

---

## 🛠️ Troubleshooting

| Issue       | Fix                                 |
| ----------- | ----------------------------------- |
| No callback | Set `FINALCALLBACKURL` correctly    |
| SSE drops   | Keepalive runs every 20s            |
| Low score   | Improve PII extraction              |
| Debugging   | Check browser console + server logs |

---


## 🤝 Contributing

PRs welcome. Just don’t break the scoring system and pretend it was a feature.

---

## 💡 Notes

* Designed for **agentic evaluation**, not static testing
* Works best with adaptive or LLM-powered honeypots
* Optimized for Indian scam ecosystems

---


**Built by The Defenders**
