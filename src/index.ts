import cors from 'cors';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

const app = express();
app.use(cors());
app.use(express.json());

// Ephemeral Session Store (In-Memory for V1 Prototype, use Redis for Production)
const sessionStore = new Map();

app.post('/api/v1/sessions', (req, res) => {
    const { verifier_name, required_claims } = req.body;
    const session_id = uuidv4();
    const nonce = uuidv4(); // Simple nonce

    const sessionData = {
        session_id,
        nonce,
        verifier_name,
        required_claims,
        status: 'PENDING',
        proof: null
    };

    sessionStore.set(session_id, sessionData);

    // QR Payload Format
    const qr_payload = {
        v: 1,
        action: 'verify',
        session_id,
        nonce,
        verifier: {
            name: verifier_name,
            did: 'did:web:relay.zeroauth.app' // Mock DID
        },
        required_claims,
        callback: `http://localhost:3000/api/v1/sessions/${session_id}/proof`
    };

    res.json({ session_id, nonce, qr_payload });
});

app.get('/api/v1/sessions/:id', (req, res) => {
    const session = sessionStore.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json(session);
});

app.post('/api/v1/sessions/:id/proof', (req, res) => {
    const session = sessionStore.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });

    session.status = 'COMPLETED';
    session.proof = req.body; // Wallet sends the ProofPayload

    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Zero Auth Relay running on port ${PORT}`);
});
