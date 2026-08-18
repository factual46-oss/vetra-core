import { z } from 'zod';

/**
 * Fonte unica dos contratos da API (Doc 05, secao 3).
 * O OpenAPI e gerado destes schemas; o web e o mobile importam daqui.
 * Assim nao existe documentacao que envelhece separada do codigo.
 */

export const provenanceType = z.enum([
  'VERIFIED',
  'PROFESSIONAL_REPORTED',
  'USER_REPORTED',
  'EXTERNAL_SOURCE',
  'SYSTEM_INFERRED',
  'UNVERIFIED',
]);
export type ProvenanceType = z.infer<typeof provenanceType>;

/** Todo fato exibido carrega sua origem (briefing secoes 95 e 96). */
export const provenance = z.object({
  level: provenanceType,
  sourceType: z.string(),
  sourceRef: z.string().nullable(),
  confidence: z.number().min(0).max(1),
  recordedAt: z.string().datetime(),
  verifiedAt: z.string().datetime().nullable(),
});
export type Provenance = z.infer<typeof provenance>;

export const problemDetails = z.object({
  type: z.string(),
  title: z.string(),
  status: z.number().int(),
  detail: z.string().optional(),
  instance: z.string().optional(),
  traceId: z.string().optional(),
  errors: z.record(z.array(z.string())).optional(),
});
export type ProblemDetails = z.infer<typeof problemDetails>;

export const healthLiveResponse = z.object({ status: z.literal('ok') });

export const healthReadyResponse = z.object({
  status: z.enum(['ok', 'error']),
  checks: z.record(
    z.object({
      status: z.enum(['ok', 'error']),
      latencyMs: z.number(),
      error: z.string().optional(),
    }),
  ),
});

/** Paginacao por cursor. Offset nao escala em tabela de eventos. */
export const cursorPage = <T extends z.ZodTypeAny>(item: T) =>
  z.object({ items: z.array(item), nextCursor: z.string().nullable() });

export const API_VERSION = 'v1' as const;
