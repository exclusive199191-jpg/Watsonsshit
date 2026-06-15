FROM node:22-alpine AS builder

RUN apk add --no-cache python3 make g++
RUN npm install -g pnpm@10

WORKDIR /app

# Copy workspace config first (better layer caching)
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY tsconfig.json tsconfig.base.json ./

# Copy library packages
COPY lib/ lib/

# Copy only the api-server artifact
COPY artifacts/api-server/ artifacts/api-server/

# Install all dependencies
RUN pnpm install --frozen-lockfile

# Compile TypeScript → dist/ via esbuild
RUN pnpm --filter @workspace/api-server run build

# ── Production image ──────────────────────────────────────────────────────────
FROM node:22-alpine AS production

WORKDIR /app

# Copy the built workspace from the builder stage
COPY --from=builder /app /app

ENV NODE_ENV=production

EXPOSE 8080

# Start the server directly — migrations run inside Node.js on startup
CMD ["node", "--enable-source-maps", "/app/artifacts/api-server/dist/index.mjs"]
