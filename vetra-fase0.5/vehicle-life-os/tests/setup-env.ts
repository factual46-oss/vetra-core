import { generateKeyPairSync } from 'node:crypto';

/**
 * Preenche o ambiente das suites ANTES de qualquer import de servico --
 * getEnv() e memoizado e os servicos leem a configuracao no construtor.
 *
 * As URLs de banco vem das variaveis TEST_*. Se elas faltarem, as suites da
 * Fase 1 FALHAM em vez de pular: SKIP nao e PASS.
 */
process.env['NODE_ENV'] ??= 'test';

/**
 * As URLs reais vem das variaveis TEST_*. Os valores de reserva existem apenas
 * para que getEnv() valide -- suites puras (dominio, JWT) constroem servicos
 * sem nunca abrir conexao. Suite que precisa de banco de verdade chama
 * requireDatabase() e FALHA com mensagem clara se as TEST_* faltarem.
 */
process.env['DATABASE_URL'] ??=
  process.env['TEST_DATABASE_URL_APP'] ?? 'postgres://vlos_app:sem-banco@127.0.0.1:5432/vlos';
process.env['DATABASE_AUTH_URL'] ??=
  process.env['TEST_DATABASE_URL_AUTH'] ?? 'postgres://vlos_auth:sem-banco@127.0.0.1:5432/vlos';
process.env['REDIS_URL'] ??= 'redis://localhost:6379';

process.env['AUTH_PEPPER_BASE64'] ??= Buffer.alloc(32, 7).toString('base64');
process.env['APP_KEK_BASE64'] ??= Buffer.alloc(32, 8).toString('base64');
process.env['IDENTIFIER_PEPPER_BASE64'] ??= Buffer.alloc(32, 9).toString('base64');
process.env['AUDIT_IP_HASH_KEY_BASE64'] ??= Buffer.alloc(32, 10).toString('base64');

// Argon2 com o minimo OWASP: a suite roda dezenas de hashes e o custo importa.
process.env['ARGON2_MEMORY_KIB'] ??= '19456';
process.env['ARGON2_TIME_COST'] ??= '2';
process.env['ARGON2_PARALLELISM'] ??= '1';

if (!process.env['JWT_KEYS_JSON'] || process.env['JWT_KEYS_JSON'] === '[]') {
  process.env['JWT_KEYS_JSON'] = JSON.stringify([
    makeKey('test-active', 'active'),
    makeKey('test-retiring', 'retiring'),
  ]);
}

function makeKey(kid: string, status: 'active' | 'next' | 'retiring') {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    kid,
    status,
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}
