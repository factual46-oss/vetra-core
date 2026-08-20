#!/usr/bin/env node
/**
 * Gera um par Ed25519 no formato esperado por JWT_KEYS_JSON.
 *
 * Rotacao em quatro tempos (D3):
 *   1. gerar com --status next  -> a chave so verifica
 *   2. deploy; todas as instancias passam a conhecer a chave
 *   3. promover a "active" e a anterior a "retiring"
 *   4. apos 1 hora de graca, remover a "retiring"
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto';

const status = process.argv.includes('--active') ? 'active' : 'next';
const kid = process.argv.find((a) => a.startsWith('--kid='))?.slice(6) ?? randomUUID().slice(0, 8);

const { publicKey, privateKey } = generateKeyPairSync('ed25519');

const key = {
  kid,
  status,
  privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
};

console.log('# Adicione ao array de JWT_KEYS_JSON (uma linha, sem quebras):');
console.log(JSON.stringify([key]));
console.error(`\n[gen-jwt-key] kid=${kid} status=${status}`);
