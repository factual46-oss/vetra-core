import { describe, expect, it } from 'vitest';
import {
  AIUnavailableError,
  DETERMINISTIC_INTENTS,
  DisabledAIProvider,
  INSUFFICIENT_DATA_ANSWER,
} from './ai-provider.js';

describe('contrato do provedor de IA', () => {
  it('falha explicitamente quando nenhum provedor esta configurado', async () => {
    const provider = new DisabledAIProvider();
    await expect(
      provider.complete(),
    ).rejects.toBeInstanceOf(AIUnavailableError);
  });

  it('mantem a resposta padrao de ausencia de dados', () => {
    // Gate item 36: sem dado, a resposta e essa -- nunca uma estimativa
    // apresentada como fato.
    expect(INSUFFICIENT_DATA_ANSWER).toBe('Não tenho dados suficientes para afirmar isso.');
  });

  it('lista as intencoes que devem ser resolvidas por SQL, nao por IA', () => {
    // Gate item 33: pergunta deterministica nao paga token.
    expect(DETERMINISTIC_INTENTS).toContain('ODOMETER_CURRENT');
    expect(DETERMINISTIC_INTENTS).toContain('LAST_OIL_CHANGE');
    expect(DETERMINISTIC_INTENTS).toContain('TOTAL_SPEND');
  });
});
