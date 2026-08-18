# syntax=docker/dockerfile:1.7
# Imagem usada por api, worker e scheduler (mesmo codigo, comandos diferentes).

FROM node:22-bookworm-slim AS base
WORKDIR /app
ENV NODE_ENV=production

FROM base AS deps
COPY package.json package-lock.json* ./
COPY apps/api/package.json apps/api/
COPY apps/worker/package.json apps/worker/
COPY packages/contracts/package.json packages/contracts/
RUN npm ci --include=dev

FROM deps AS build
COPY tsconfig.base.json ./
COPY packages ./packages
COPY apps ./apps
RUN npm run build --workspaces --if-present

FROM base AS runtime
# Nunca root (Doc 04, secao 2)
RUN groupadd --system --gid 1001 vlos && useradd --system --uid 1001 --gid vlos vlos
COPY --from=deps  --chown=vlos:vlos /app/node_modules ./node_modules
COPY --from=build --chown=vlos:vlos /app/apps ./apps
COPY --from=build --chown=vlos:vlos /app/packages ./packages
COPY --chown=vlos:vlos db ./db
COPY --chown=vlos:vlos tools ./tools
COPY --chown=vlos:vlos package.json ./
USER vlos
EXPOSE 3000
CMD ["node", "apps/api/dist/main.js"]

# Estagio de desenvolvimento: dependencias vem da imagem, codigo vem por bind
# mount. O volume anonimo em /app/node_modules preserva o que foi instalado aqui.
FROM deps AS dev
ENV NODE_ENV=development
CMD ["npm", "run", "dev", "--workspace", "@vlos/api"]
