/**
 * Politica de senha.
 *
 * Sem regras de composicao (maiuscula, numero, simbolo): elas empurram o usuario
 * para padroes previsiveis -- "Senha1!" -- sem ganho real de entropia. Comprimento
 * minimo e o unico criterio com efeito comprovado, alinhado ao NIST SP 800-63B.
 *
 * Teto de 1024 caracteres: a senha passa por HMAC antes do Argon2, entao entrada
 * gigante nao encarece o hash, mas evita alocacao absurda vinda da rede.
 */

export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 1024;

export type PasswordRejection = 'TOO_SHORT' | 'TOO_LONG' | 'ONLY_WHITESPACE' | 'REPEATED_CHARACTER';

export interface PasswordCheck {
  ok: boolean;
  rejection?: PasswordRejection;
}

export function checkPassword(password: string): PasswordCheck {
  if (typeof password !== 'string' || password.trim().length === 0) {
    return { ok: false, rejection: 'ONLY_WHITESPACE' };
  }
  if (password.length < PASSWORD_MIN_LENGTH) return { ok: false, rejection: 'TOO_SHORT' };
  if (password.length > PASSWORD_MAX_LENGTH) return { ok: false, rejection: 'TOO_LONG' };
  // "aaaaaaaaaaaa" tem comprimento suficiente e entropia nenhuma
  if (/^(.)\1+$/u.test(password)) return { ok: false, rejection: 'REPEATED_CHARACTER' };
  return { ok: true };
}

/**
 * DEFERRED TO PHASE 1B: verificacao contra senhas vazadas por k-anonymity (HIBP).
 * Exige chamada de rede de saida, que ainda nao existe no perimetro da API.
 */
