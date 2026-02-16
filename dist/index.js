"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const cors_1 = __importDefault(require("cors"));
const express_1 = __importDefault(require("express"));
const uuid_1 = require("uuid");
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
app.use(express_1.default.json());
// Ephemeral Session Store (In-Memory for V1 Prototype, use Redis for Production)
const sessionStore = new Map();
app.post('/api/v1/sessions', (req, res) => {
    const { verifier_name, required_claims } = req.body;
    const session_id = (0, uuid_1.v4)();
    const nonce = (0, uuid_1.v4)(); // Simple nonce
    const sessionData = {
        session_id,
        nonce,
        verifier_name,
        required_claims,
        status: 'PENDING',
        proof: null,
        expires_at: Date.now() + 5 * 60 * 1000 // 5 minutes
    };
    sessionStore.set(session_id, sessionData);
    // Auto-cleanup after 6 minutes
    setTimeout(() => {
        if (sessionStore.has(session_id)) {
            sessionStore.delete(session_id);
            console.log(`Session ${session_id} expired and removed.`);
        }
    }, 6 * 60 * 1000);
    // QR Payload Format
    const qr_payload = {
        v: 1,
        action: 'verify',
        session_id,
        nonce,
        verifier: {
            name: verifier_name,
            did: 'did:web:relay.zeroauth.app', // Mock DID
            callback: `http://localhost:3000/api/v1/sessions/${session_id}/proof`
        },
        required_claims,
        credential_type: 'Age Verification', // Default for V1
        expires_at: Math.floor((Date.now() + 5 * 60 * 1000) / 1000) // Unix timestamp (5 mins)
    };
    res.json({ session_id, nonce, qr_payload });
});
app.get('/api/v1/sessions/:id', (req, res) => {
    const session = sessionStore.get(req.params.id);
    if (!session)
        return res.status(404).json({ error: 'Session not found' });
    res.json(session);
});
app.post('/api/v1/sessions/:id/proof', (req, res) => {
    const session = sessionStore.get(req.params.id);
    if (!session)
        return res.status(404).json({ error: 'Session not found' });
    session.status = 'COMPLETED';
    session.proof = req.body; // Wallet sends the ProofPayload
    res.json({ success: true });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Zero Auth Relay running on port ${PORT}`);
});
