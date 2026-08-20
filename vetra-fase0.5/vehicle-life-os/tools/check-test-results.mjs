#!/usr/bin/env node
/**
 * Item 33 do escopo da Fase 1: SKIP != PASS.
 *
 * O workflow pode ficar verde com dezenas de testes pulados -- foi assim que um
 * falso positivo passou na validacao da Fase 0.5. Este script le a saida do
 * vitest e falha se qualquer teste das suites obrigatorias tiver sido pulado,
 * marcado como todo, ou se a suite simplesmente nao tiver sido coletada.
 */
import { readFile } from 'node:fs/promises';

const REQUIRED_SUITES = [
  'tests/security/isolation.spec.ts',
  'tests/security/audit-chain.spec.ts',
  'tests/security/auth-privileges.spec.ts',
  'tests/security/authorization-confusion.spec.ts',
  'tests/security/connection-reuse.spec.ts',
  'tests/db/schema.spec.ts',
  'tests/auth/domain.spec.ts',
  'tests/auth/jwt.spec.ts',
  'tests/auth/registration-login.spec.ts',
  'tests/auth/refresh.spec.ts',
  'tests/auth/session-logout.spec.ts',
  'tests/auth/rate-limit.spec.ts',
];

const path = process.argv[2] ?? 'test-results.json';
const report = JSON.parse(await readFile(path, 'utf8'));

const results = report.testResults ?? [];
let passed = 0;
let failed = 0;
let skipped = 0;
let todo = 0;
const problems = [];

for (const file of results) {
  for (const test of file.assertionResults ?? []) {
    if (test.status === 'passed') passed++;
    else if (test.status === 'failed') { failed++; problems.push(`FAILED  ${test.fullName}`); }
    else if (test.status === 'todo') { todo++; problems.push(`TODO    ${test.fullName}`); }
    else { skipped++; problems.push(`SKIPPED ${test.fullName}`); }
  }
}

const collected = new Set(results.map((f) => String(f.name).replace(/\\/g, '/')));
for (const suite of REQUIRED_SUITES) {
  if (![...collected].some((name) => name.endsWith(suite))) {
    problems.push(`NOT RUN ${suite}  <-- suite obrigatoria nao foi coletada`);
  }
}

console.log('─'.repeat(60));
console.log(`Test Files : ${results.length}`);
console.log(`Tests      : ${passed + failed + skipped + todo}`);
console.log(`Passed     : ${passed}`);
console.log(`Failed     : ${failed}`);
console.log(`Skipped    : ${skipped}`);
console.log(`Todo       : ${todo}`);
console.log('─'.repeat(60));

if (problems.length > 0) {
  console.error('\nProblemas:');
  for (const p of problems) console.error(`  ${p}`);
  console.error('\nSKIP != PASS. TODO != PASS. NOT RUN != PASS.');
  process.exit(1);
}
console.log('Todas as suites obrigatorias executaram sem skip e sem todo.');
