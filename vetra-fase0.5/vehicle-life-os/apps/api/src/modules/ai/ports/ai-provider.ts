/**
 * Porta do provedor de IA (gate itens 31 a 36).
 *
 * O dominio conhece APENAS esta interface. Trocar Anthropic por OpenAI, Gemini
 * ou um modelo local e escrever um adaptador novo e mudar uma variavel de
 * ambiente -- nenhum caso de uso muda.
 *
 * Regra economica do MVP: UM provedor ativo por vez. A interface existe para
 * permitir a troca, nao para orquestrar varios fornecedores pagos ao mesmo tempo.
 */

export interface AICompletionRequest {
  /** Instrucoes do sistema. Nunca contem dado de usuario. */
  system: string;
  /** Pergunta do usuario, ja normalizada. */
  prompt: string;
  /**
   * Contexto recuperado do banco (gate item 34).
   * Cada item carrega sua origem para que a resposta possa citar a fonte e para
   * que o modelo nunca seja o dono do fato.
   */
  context: RetrievedFact[];
  maxOutputTokens: number;
  timeoutMs: number;
}

export interface RetrievedFact {
  factId: string;
  summary: string;
  provenance: string;
  occurredAt: string | null;
  /**
   * Conteudo vindo de documento enviado pelo usuario e potencialmente hostil
   * (prompt injection). O adaptador precisa delimita-lo como DADO, nunca como
   * instrucao. Doc 03, secao 6.
   */
  untrusted: boolean;
}

export interface AICompletionResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
  costCents: number;
  model: string;
  /** true quando o resultado veio do cache e nao gerou custo. */
  cached: boolean;
}

export interface AIProvider {
  readonly name: string;
  complete(request: AICompletionRequest): Promise<AICompletionResult>;
}

export const AI_PROVIDER = Symbol('AI_PROVIDER');

/**
 * Guarda de orcamento (gate item 32). Interface separada do provedor de
 * proposito: o controle de custo nao pode depender da implementacao do
 * fornecedor, senao trocar de fornecedor perde o controle de custo junto.
 */
export interface AIBudgetGuard {
  assertWithinBudget(userId: string, estimatedTokens: number): Promise<void>;
  record(userId: string, result: AICompletionResult): Promise<void>;
}

export const AI_BUDGET_GUARD = Symbol('AI_BUDGET_GUARD');

/**
 * Erro lancado quando a IA nao pode ser usada. A API traduz para uma resposta
 * honesta -- nunca para uma resposta inventada.
 */
export class AIUnavailableError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'AIUnavailableError';
  }
}

/**
 * Implementacao usada quando AI_PROVIDER=none (padrao da Fase 0).
 * Falha alto e claro. O que NAO se faz aqui e devolver texto plausivel:
 * uma resposta fabricada sobre manutencao de veiculo e pior que erro nenhum.
 */
export class DisabledAIProvider implements AIProvider {
  readonly name = 'none';

  async complete(): Promise<AICompletionResult> {
    throw new AIUnavailableError(
      'Nenhum provedor de IA configurado. Defina AI_PROVIDER e as variaveis de orcamento.',
    );
  }
}

/**
 * Perguntas deterministicas nao vao para a IA (gate item 33).
 * "Qual a quilometragem?" e uma consulta SQL. Passar isso por um modelo custa
 * dinheiro, adiciona latencia e introduz risco de erro numa resposta que o
 * banco daria exata.
 */
export const DETERMINISTIC_INTENTS = [
  'ODOMETER_CURRENT',
  'LAST_OIL_CHANGE',
  'MAINTENANCE_DUE',
  'TOTAL_SPEND',
  'DOCUMENT_EXPIRY',
  'EVENT_COUNT',
] as const;

export type DeterministicIntent = (typeof DETERMINISTIC_INTENTS)[number];

/** Resposta padrao quando falta dado (gate item 36). */
export const INSUFFICIENT_DATA_ANSWER =
  'Não tenho dados suficientes para afirmar isso.';
