import { z } from 'zod';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '../domain/password-policy.js';

/**
 * Contratos de entrada. `strict()` recusa campo desconhecido em vez de ignorar:
 * um cliente que envia `isAdmin: true` recebe 400, nao um silencio que sugere
 * que o campo foi aceito.
 */
export const registerSchema = z
  .object({
    email: z.string().min(3).max(254),
    password: z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH),
    displayName: z.string().min(1).max(120),
  })
  .strict();

export const loginSchema = z
  .object({
    email: z.string().min(3).max(254),
    password: z.string().min(1).max(PASSWORD_MAX_LENGTH),
    /** Cookie para o cliente web (via BFF); bearer para mobile e parceiros. */
    transport: z.enum(['bearer', 'cookie']).default('bearer'),
  })
  .strict();

export const refreshSchema = z
  .object({ refreshToken: z.string().min(1).max(512).optional() })
  .strict();

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
