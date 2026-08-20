/**
 * Politica UNICA de normalizacao de e-mail (item 8 do escopo).
 * Usada em cadastro, login, recuperacao, verificacao e qualquer consulta de
 * identidade. Se houver duas normalizacoes no sistema, existem duas identidades.
 *
 * A politica:
 *   1. NFKC  -- caracteres visualmente identicos passam a ter a mesma forma
 *   2. trim
 *   3. minusculas
 *
 * O que deliberadamente NAO fazemos: remover pontos e sufixos "+tag". Isso e
 * comportamento especifico do Gmail. Aplicar a todo mundo fundiria identidades
 * legitimamente distintas em provedores que tratam `a.b@` e `ab@` como caixas
 * diferentes -- e fundir contas e irreversivel.
 */

export class InvalidEmailError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'InvalidEmailError';
  }
}

const MAX_LENGTH = 254; // RFC 5321
const SHAPE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/u;

export function normalizeEmail(raw: string): string {
  if (typeof raw !== 'string') throw new InvalidEmailError('e-mail ausente');

  const normalized = raw.normalize('NFKC').trim().toLowerCase();

  if (normalized.length === 0) throw new InvalidEmailError('e-mail vazio');
  if (normalized.length > MAX_LENGTH) throw new InvalidEmailError('e-mail longo demais');
  if (!SHAPE.test(normalized)) throw new InvalidEmailError('formato de e-mail invalido');
  // Caracteres de controle nao sao barrados pelo formato acima
  if (/[\u0000-\u001f\u007f]/u.test(normalized)) throw new InvalidEmailError('e-mail invalido');

  return normalized;
}

export function isValidEmail(raw: string): boolean {
  try {
    normalizeEmail(raw);
    return true;
  } catch {
    return false;
  }
}
