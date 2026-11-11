# syntax=docker/dockerfile:1
FROM node:22-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/tsconfig.json ./packages/protocol/
COPY packages/coordinator/package.json packages/coordinator/tsconfig.json ./packages/coordinator/
COPY packages/server/package.json packages/server/tsconfig.json ./packages/server/
COPY packages/cli/package.json packages/cli/tsconfig.json ./packages/cli/

RUN npm ci --no-audit --no-fund

COPY packages/protocol/src ./packages/protocol/src
COPY packages/coordinator/src ./packages/coordinator/src
COPY packages/server/src ./packages/server/src
COPY packages/cli/src ./packages/cli/src

RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8787
ENV STUN_PORT=3478
ENV DATA_DIR=/data

COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/packages/protocol/package.json ./packages/protocol/
COPY --from=builder /app/packages/protocol/dist ./packages/protocol/dist
COPY --from=builder /app/packages/coordinator/package.json ./packages/coordinator/
COPY --from=builder /app/packages/coordinator/dist ./packages/coordinator/dist
COPY --from=builder /app/packages/server/package.json ./packages/server/
COPY --from=builder /app/packages/server/dist ./packages/server/dist
COPY scripts ./scripts

RUN npm ci --omit=dev --no-audit --no-fund \
      --workspace=@beamsync/protocol \
      --workspace=@beamsync/coordinator \
      --workspace=@beamsync/server && \
    mkdir -p /data && chown -R node:node /data /app
USER node

EXPOSE 8787/tcp
EXPOSE 3478/udp
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/healthz >/dev/null || exit 1

CMD ["node", "packages/server/dist/bin.js"]
