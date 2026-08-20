import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { InvalidTokenError, JwtService } from '../../apps/api/src/modules/auth/infra/jwt.service.js';

/**
 * Access token e adulteracao (D3, oito ataques homologados).
 *
 * Nao precisa de banco: prova exclusivamente o que a assinatura garante -- e,
 * por consequencia, o que ela NAO garante, que e o vinculo sid<->sub, coberto
 * na suite de confusao de autorizacao.
 */
describe('access token EdDSA', () => {
  let jwt: JwtService;
  let foreignPrivatePem: string;

  beforeAll(() => {
    jwt = new JwtService();
    const pair = generateKeyPairSync('ed25519');
    foreignPrivatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  });

  const sign = () =>
    jwt.sign({ userId: '11111111-1111-4111-8111-111111111111', sessionId: '22222222-2222-4222-8222-222222222222', amr: ['pwd'] });

  it('assina e verifica, devolvendo as claims minimas', async () => {
    const { token } = await sign();
    const claims = await jwt.verify(token);
    expect(claims.sub).toBe('11111111-1111-4111-8111-111111111111');
    expect(claims.sid).toBe('22222222-2222-4222-8222-222222222222');
    expect(claims.amr).toEqual(['pwd']);
  });

  it('nao carrega dado pessoal nem claim de autorizacao', async () => {
    const { token } = await sign();
    const payload = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;
    for (const forbidden of ['email', 'name', 'displayName', 'is_admin', 'isAdmin', 'role', 'permissions', 'password']) {
      expect(payload[forbidden]).toBeUndefined();
    }
  });

  it('usa a chave active e anuncia o kid', async () => {
    const { token } = await sign();
    const header = JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()) as { alg: string; kid: string };
    expect(header.alg).toBe('EdDSA');
    expect(header.kid).toBe('test-active');
  });

  // --- ataques de adulteracao -------------------------------------------------

  it('1. recusa payload alterado com assinatura original', async () => {
    const { token } = await sign();
    const [header, payload, signature] = token.split('.');
    const tampered = JSON.parse(Buffer.from(payload!, 'base64url').toString()) as Record<string, unknown>;
    tampered['sub'] = '33333333-3333-4333-8333-333333333333';
    const forged = `${header}.${Buffer.from(JSON.stringify(tampered)).toString('base64url')}.${signature}`;
    await expect(jwt.verify(forged)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('2. recusa token assinado por chave estranha', async () => {
    const key = await importPKCS8(foreignPrivatePem, 'EdDSA');
    const forged = await new SignJWT({ sid: 'x', amr: ['pwd'] })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-active' })
      .setSubject('invasor')
      .setIssuer('vetra')
      .setAudience('vetra-api')
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(key);
    await expect(jwt.verify(forged)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('3. recusa alg: none', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', kid: 'test-active' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'x', sid: 'y', amr: [] })).toString('base64url');
    await expect(jwt.verify(`${header}.${payload}.`)).rejects.toMatchObject({ kind: 'BAD_ALGORITHM' });
  });

  it('4. recusa confusao de algoritmo: HS256 com a chave publica como segredo', async () => {
    // O ataque classico contra JWT. A whitelist algorithms:['EdDSA'] e o que o barra.
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', kid: 'test-active' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ sub: 'x', sid: 'y', amr: [] })).toString('base64url');
    await expect(jwt.verify(`${header}.${payload}.assinatura`)).rejects.toMatchObject({
      kind: 'BAD_ALGORITHM',
    });
  });

  it('5. recusa kid inexistente', async () => {
    const key = await importPKCS8(foreignPrivatePem, 'EdDSA');
    const forged = await new SignJWT({ sid: 'y', amr: [] })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'chave-que-nao-existe' })
      .setSubject('x')
      .setIssuer('vetra')
      .setAudience('vetra-api')
      .setExpirationTime('10m')
      .sign(key);
    await expect(jwt.verify(forged)).rejects.toMatchObject({ kind: 'UNKNOWN_KID' });
  });

  it('6. recusa token cujo kid aponta para outra chave do conjunto', async () => {
    const { token } = await sign();
    const [, payload, signature] = token.split('.');
    const swapped = Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'test-retiring', typ: 'JWT' })).toString('base64url');
    await expect(jwt.verify(`${swapped}.${payload}.${signature}`)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('7. recusa token expirado', async () => {
    const keys = JSON.parse(process.env['JWT_KEYS_JSON']!) as { kid: string; privatePem: string }[];
    const active = keys.find((k) => k.kid === 'test-active')!;
    const expired = await new SignJWT({ sid: 'y', amr: [] })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-active' })
      .setSubject('x')
      .setIssuer('vetra')
      .setAudience('vetra-api')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(await importPKCS8(active.privatePem, 'EdDSA'));
    await expect(jwt.verify(expired)).rejects.toMatchObject({ kind: 'EXPIRED' });
  });

  it('8. recusa issuer e audience incorretos', async () => {
    const keys = JSON.parse(process.env['JWT_KEYS_JSON']!) as { kid: string; privatePem: string }[];
    const active = keys.find((k) => k.kid === 'test-active')!;
    const wrong = await new SignJWT({ sid: 'y', amr: [] })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-active' })
      .setSubject('x')
      .setIssuer('outro-emissor')
      .setAudience('outra-audiencia')
      .setExpirationTime('10m')
      .sign(await importPKCS8(active.privatePem, 'EdDSA'));
    await expect(jwt.verify(wrong)).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('recusa token malformado', async () => {
    await expect(jwt.verify('isto.nao.e-token')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('recusa token sem a claim sid', async () => {
    const keys = JSON.parse(process.env['JWT_KEYS_JSON']!) as { kid: string; privatePem: string }[];
    const active = keys.find((k) => k.kid === 'test-active')!;
    const noSid = await new SignJWT({ amr: [] })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'test-active' })
      .setSubject('x')
      .setIssuer('vetra')
      .setAudience('vetra-api')
      .setExpirationTime('10m')
      .sign(await importPKCS8(active.privatePem, 'EdDSA'));
    await expect(jwt.verify(noSid)).rejects.toMatchObject({ kind: 'BAD_CLAIMS' });
  });
});
