/*
 * RFC 7807.
 *
 * AUD-18: este modulo nao importa nada do framework. A forma do erro e regra do
 * produto, nao detalhe do Nest -- assim o formato pode ser testado sozinho e
 * reaproveitado por qualquer cliente.
 * Formato unico de erro para toda a API (Doc 05, secao 3).
 *
 * Regra de seguranca (Doc 03, secao 3): recurso existente sem permissao
 * responde 404, nunca 403 -- 403 confirma a existencia do recurso, e no caso
 * de placas e chassis isso ja e vazamento.
 */
export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  traceId?: string;
  errors?: Record<string, string[]>;
}

const TITLES: Record<number, string> = {
  400: 'Requisição inválida',
  401: 'Não autenticado',
  403: 'Ação não permitida',
  404: 'Recurso não encontrado',
  409: 'Conflito de estado',
  422: 'Não foi possível processar',
  429: 'Muitas requisições',
  500: 'Erro interno',
  503: 'Serviço indisponível',
};

/**
 * CI-02: cada opcional declara `| undefined`. E o que o TS2375 do pipeline
 * cobrava: quem chama monta o objeto a partir de valores que podem ser
 * indefinidos, e obrigar cada chamador a montar o literal condicionalmente
 * empurraria ruido para todos eles.
 */
export interface ProblemOptions {
  detail?: string | undefined;
  instance?: string | undefined;
  traceId?: string | undefined;
  errors?: Record<string, string[]> | undefined;
}

export function problemFor(status: number, options: ProblemOptions = {}): ProblemDetails {
  const problem: ProblemDetails = {
    type: `https://docs.vehiclelifeos.com/errors/${status}`,
    title: TITLES[status] ?? 'Erro',
    status,
  };
  // 5xx nunca carrega detalhe: mensagem interna pode conter estrutura do sistema.
  if (options.detail && status < 500) problem.detail = options.detail;
  if (options.instance) problem.instance = options.instance;
  if (options.traceId) problem.traceId = options.traceId;
  if (options.errors && status < 500) problem.errors = options.errors;
  return problem;
}
