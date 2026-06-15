FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++
RUN npm install -g pnpm@10

WORKDIR /app

# Copy workspace config first (better layer caching)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY tsconfig.json tsconfig.base.json ./

# Copy library packages
COPY lib/ lib/

# Copy only the api-server artifact (not the mockup sandbox)
COPY artifacts/api-server/ artifacts/api-server/

# Install all dependencies (dev deps needed for build + drizzle-kit)
RUN pnpm install --frozen-lockfile

# Build the api-server (compiles TypeScript via esbuild into dist/)
RUN pnpm --filter @workspace/api-server run build

# ── Production image ──────────────────────────────────────────────────────────
FROM node:22-alpine AS production

RUN npm install -g pnpm@10

WORKDIR /app

# Copy the full workspace from builder (needed so drizzle-kit can read schema TS files at startup)
COPY --from=builder /app /app

ENV NODE_ENV=production

EXPOSE 8080

# On startup: push DB schema then start the server
CMD sh -c "pnpm --filter @workspace/db run push && node --enable-source-maps /app/artifacts/api-server/dist/index.mjs"
