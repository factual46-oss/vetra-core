/**
 * Registro unico de filas (Doc 01, secao 4).
 * Declarar aqui e o que impede que cada fase invente um nome de fila proprio.
 */
export const QUEUES = {
  ANTIVIRUS: 'antivirus',
  OCR: 'ocr',
  AI: 'ai',
  ALERTS: 'alerts',
  MAINTENANCE_RECALC: 'maintenance-recalc',
  NOTIFICATIONS: 'notifications',
  EXPORTS: 'exports',
  AUDIT_VERIFY: 'audit-verify',
} as const;

export type QueueName = (typeof QUEUES)[keyof typeof QUEUES];

/**
 * Politica padrao de retry. Job que falha nao pode sumir em silencio:
 * apos as tentativas, permanece na dead letter para inspecao.
 */
export const DEFAULT_JOB_OPTIONS = {
  attempts: 5,
  backoff: { type: 'exponential' as const, delay: 5_000 },
  removeOnComplete: { age: 86_400, count: 1_000 },
  removeOnFail: false,
} as const;
