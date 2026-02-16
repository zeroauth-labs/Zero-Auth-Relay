import { createClient } from 'redis';
import { env } from '../config';

const client = createClient({
    url: env.REDIS_URL
});

client.on('error', (err) => console.error('Redis Client Error', err));

let isConnected = false;

export const getRedisClient = async () => {
    if (!isConnected) {
        await client.connect();
        isConnected = true;
    }
    return client;
};

export const SessionStore = {
    getRedisClient,
    async set(sessionId: string, data: any, ttlSeconds: number = 300) {
        const client = await getRedisClient();
        await client.setEx(`session:${sessionId}`, ttlSeconds, JSON.stringify(data));
    },

    async get(sessionId: string) {
        const client = await getRedisClient();
        const data = await client.get(`session:${sessionId}`);
        return data ? JSON.parse(data) : null;
    },

    async delete(sessionId: string) {
        const client = await getRedisClient();
        await client.del(`session:${sessionId}`);
    }
};
