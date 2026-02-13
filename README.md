# Zero Auth Relay 🛰️
[![Organization](https://img.shields.io/badge/Organization-zeroauth--labs-blue.svg)](https://github.com/zeroauth-labs)

The **Zero Auth Relay** is a stateless communication hub that bridges the gap between Web Applications (requesting verification) and the Mobile Wallet (generating proofs).

## 🧩 How it Works
The relay doesn't store any Permanent Identity Information (PII). Its sole responsibility is to manage ephemeral "Verification Sessions".

1. **Session Creation**: A Web App (via the SDK) creates a session on the Relay.
2. **QR Generation**: The Relay provides the metadata for a QR code.
3. **Wallet Interaction**: The Mobile Wallet scans the QR, generates a ZK Proof, and pushes it back to the Relay.
4. **Resolution**: The SDK polls the Relay (or uses WebSockets) to receive the proof confirmation.

## 📡 API Specification (v1)

### 1. `POST /api/v1/sessions`
Inititate a new verification request.
- **Request Body**:
  ```json
  {
    "verifier_name": "My App",
    "required_claims": ["age_over_18"],
    "callback_url": "https://myapp.com/api/verified" (Optional)
  }
  ```
- **Response**: `session_id`, `nonce`, `qr_payload`.

### 2. `GET /api/v1/sessions/:id`
Check the status of a specific session.
- **Status Codes**: `PENDING`, `SCANNED`, `COMPLETED`, `EXPIRED`.

### 3. `POST /api/v1/sessions/:id/proof`
Endpoint for the mobile wallet to submit the generated ZK proof.

---

## 🛠️ Stack
- **Runtime**: Node.js
- **Framework**: Express / Fastify (TypeScript)
- **State**: Redis (Ephemeral storage with 10-minute TTL)

## 🎨 Development Style
- Keep it lightweight and stateless.
- Use strict JSON Schema validation for all payloads.
- Prioritize high throughput and low latency.

---
Built by [Zero Auth Labs](https://github.com/zeroauth-labs)
