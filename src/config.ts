import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const configSchema = z.object({
    PORT: z.string().default('3000'),
    REDIS_URL: z.string().default('redis://localhost:6379'),
    RELAY_DID: z.string().default('did:web:relay.zeroauth.app'),
    LOG_LEVEL: z.enum(['info', 'debug', 'error', 'warn']).default('info'),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

const result = configSchema.safeParse(process.env);

if (!result.success) {
    console.error('Invalid configuration:', result.error.format());
    process.exit(1);
}

export const env = result.data;
