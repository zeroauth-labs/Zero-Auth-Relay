import fs from 'fs';
import path from 'path';

// ZK Engine (Server side)
const { groth16 } = require('snarkjs');

const VKEY_DIR = path.resolve(__dirname, '../../circuits');

export interface ZKProof {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
    publicSignals: string[];
}

export const verifyProof = async (proofPayload: ZKProof, credentialType: string = 'Age Verification'): Promise<boolean> => {
    try {
        const vKeyFile = credentialType === 'Student ID' ? 'student_check_vKey.json' : 'age_check_vKey.json';
        const vKeyPath = path.join(VKEY_DIR, vKeyFile);

        if (!fs.existsSync(vKeyPath)) {
            console.error(`Verification key not found: ${vKeyPath}`);
            return false;
        }

        const vKey = JSON.parse(fs.readFileSync(vKeyPath, 'utf8'));

        // Format proof for snarkjs
        const proof = {
            pi_a: proofPayload.pi_a,
            pi_b: proofPayload.pi_b,
            pi_c: proofPayload.pi_c,
            protocol: proofPayload.protocol,
            curve: proofPayload.curve
        };

        const isValid = await groth16.verify(vKey, proofPayload.publicSignals, proof);
        return isValid;
    } catch (error) {
        console.error('ZK Verification Error:', error);
        return false;
    }
};
