import cors from 'cors';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import { z } from 'zod';
import pino from 'pino';
import rateLimit from 'express-rate-limit';
import { env } from './config';
import { SessionStore } from './lib/redis';
import { verifyProof } from './lib/verifier';

const logger = pino({ level: env.LOG_LEVEL });
const app = express();

// Security Middleware
app.use(cors());
app.use(express.json());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

// Schemas
const CreateSessionSchema = z.object({
    verifier_name: z.string().min(1),
    required_claims: z.array(z.string()),
    credential_type: z.string().optional().default('Age Verification')
});

const ProofPayloadSchema = z.object({
    pi_a: z.array(z.string()),
    pi_b: z.array(z.array(z.string())),
    pi_c: z.array(z.string()),
    protocol: z.string(),
    curve: z.string(),
    publicSignals: z.array(z.string())
});

// Endpoints
app.post('/api/v1/sessions', async (req, res) => {
    try {
        const validated = CreateSessionSchema.parse(req.body);
        const session_id = uuidv4();
        const nonce = uuidv4();

        const sessionData = {
            session_id,
            nonce,
            verifier_name: validated.verifier_name,
            required_claims: validated.required_claims,
            credential_type: validated.credential_type, // Persist this!
            status: 'PENDING',
            proof: null,
            expires_at: Date.now() + 5 * 60 * 1000
        };

        await SessionStore.set(session_id, sessionData);

        const qr_payload = {
            v: 1,
            action: 'verify',
            session_id,
            nonce,
            verifier: {
                name: validated.verifier_name,
                did: env.RELAY_DID,
                callback: `https://${req.get('host')}/api/v1/sessions/${session_id}/proof`
            },
            required_claims: validated.required_claims,
            credential_type: validated.credential_type,
            expires_at: Math.floor((Date.now() + 5 * 60 * 1000) / 1000)
        };

        logger.info({ session_id }, 'Session created');
        res.json({ session_id, nonce, qr_payload });
    } catch (e: any) {
        logger.error(e);
        res.status(400).json({ error: e.message });
    }
});

app.get('/api/v1/sessions/:id', async (req, res) => {
    const session = await SessionStore.get(req.params.id);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    res.json(session);
});

app.post('/api/v1/sessions/:id/proof', async (req, res) => {
    try {
        const session = await SessionStore.get(req.params.id);
        if (!session) return res.status(404).json({ error: 'Session not found' });

        if (session.status === 'COMPLETED') {
            return res.status(400).json({ error: 'Session already completed' });
        }

        const proofPayload = ProofPayloadSchema.parse(req.body);

        // REAL ZK VERIFICATION
        logger.info({ session_id: req.params.id, type: session.credential_type }, 'Verifying ZK Proof...');
        const isValid = await verifyProof(proofPayload, session.credential_type);

        if (!isValid) {
            logger.warn({ session_id: req.params.id }, 'Proof Invalid');
            return res.status(400).json({ error: 'Invalid ZK Proof' });
        }

        logger.info({ session_id: req.params.id }, 'Proof Validated Successfully');

        session.status = 'COMPLETED';
        session.proof = proofPayload;
        await SessionStore.set(req.params.id, session);

        res.json({ success: true });
    } catch (e: any) {
        logger.error(e);
        res.status(400).json({ error: e.message });
    }
});

app.delete('/api/v1/sessions/:id', async (req, res) => {
    try {
        const session = await SessionStore.get(req.params.id);
        if (!session) return res.status(404).json({ error: 'Session not found' });

        session.status = 'REVOKED';
        await SessionStore.set(req.params.id, session);

        logger.info({ session_id: req.params.id }, 'Session revoked');
        res.json({ success: true });
    } catch (e: any) {
        logger.error(e);
        res.status(400).json({ error: e.message });
    }
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Background Job: Cleanup stale sessions (every 30 mins)
const CLEANUP_INTERVAL = 30 * 60 * 1000;
setInterval(async () => {
    try {
        const client = await SessionStore.getRedisClient();
        const keys = await client.keys('session:*');
        logger.info({ keys_count: keys.length }, 'Scanning for stale sessions...');

        for (const key of keys) {
            const data = await client.get(key);
            if (!data) continue;

            const session = JSON.parse(data);
            const isStale = session.status === 'EXPIRED' || session.status === 'REVOKED';
            const isOld = Date.now() > (session.expires_at + 60 * 60 * 1000); // 1 hour past expiry

            if (isStale || isOld) {
                await client.del(key);
                logger.info({ session_id: key.split(':')[1] }, 'Cleaned up stale session');
            }
        }
    } catch (e) {
        logger.error(e, 'Session cleanup failed');
    }
}, CLEANUP_INTERVAL);

app.listen(env.PORT, () => {
    logger.info(`Zero Auth Relay running on port ${env.PORT} [${env.NODE_ENV}]`);
});
