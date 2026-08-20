#!/usr/bin/env node
/**
 * Benchmark do Argon2id NO HARDWARE REAL.
 *
 * Os valores padrao do .env.example sao ponto de partida, nao conclusao. Rode
 * isto no servidor dedicado e registre a saida no documento de decisoes.
 *
 *   node tools/bench-argon2.mjs
 *   node tools/bench-argon2.mjs --memory 65536 --time 3 --parallelism 1
 *
 * Metas (secao 11 do plano da Fase 1):
 *   hash e verify isolados : <= 250 ms
 *   p95 sob 8 simultaneos  : <= 1 s
 *   pico de RSS            : precisa caber com folga na RAM da API
 */
import { hash, verify, Algorithm } from '@node-rs/argon2';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? Number(process.argv[i + 1]) : fallback;
};

const options = {
  algorithm: Algorithm.Argon2id,
  memoryCost: arg('memory', 19456),
  timeCost: arg('time', 3),
  parallelism: arg('parallelism', 1),
};

const PASSWORD = Buffer.alloc(32, 42); // entrada ja derivada por HMAC, como em producao

async function measure(concurrency) {
  const before = process.memoryUsage().rss;
  const started = process.hrtime.bigint();

  const durations = await Promise.all(
    Array.from({ length: concurrency }, async () => {
      const t0 = process.hrtime.bigint();
      const digest = await hash(PASSWORD, options);
      const t1 = process.hrtime.bigint();
      await verify(digest, PASSWORD, options);
      const t2 = process.hrtime.bigint();
      return { hash: Number(t1 - t0) / 1e6, verify: Number(t2 - t1) / 1e6 };
    }),
  );

  const wall = Number(process.hrtime.bigint() - started) / 1e6;
  const peak = (process.memoryUsage().rss - before) / 1024 / 1024;
  const sorted = durations.map((d) => d.hash).sort((a, b) => a - b);
  const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];

  return {
    concurrency,
    hashMedio: avg(durations.map((d) => d.hash)),
    verifyMedio: avg(durations.map((d) => d.verify)),
    p95,
    wall,
    rssDeltaMiB: peak,
  };
}

const avg = (xs) => xs.reduce((a, b) => a + b, 0) / xs.length;
const fmt = (n) => `${n.toFixed(1)}`.padStart(8);

console.log(`Argon2id  m=${options.memoryCost} KiB  t=${options.timeCost}  p=${options.parallelism}`);
console.log(`Memoria teorica por hash: ${(options.memoryCost / 1024).toFixed(1)} MiB\n`);
console.log('conc.   hash(ms)  verify(ms)   p95(ms)  parede(ms)  RSS(MiB)');
console.log('─'.repeat(62));

await hash(PASSWORD, options); // aquecimento: descarta o custo do primeiro carregamento

for (const concurrency of [1, 4, 8, 16, 32]) {
  const r = await measure(concurrency);
  console.log(
    `${String(r.concurrency).padStart(5)} ${fmt(r.hashMedio)} ${fmt(r.verifyMedio)} ${fmt(r.p95)} ${fmt(r.wall)} ${fmt(r.rssDeltaMiB)}`,
  );
}

console.log('\nSe o p95 sob 8 simultaneos passar de 1 s, reduza timeCost antes de reduzir memoryCost:');
console.log('memoria e o que encarece o ataque com GPU.');
