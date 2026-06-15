FROM node:22-alpine

RUN apk add --no-cache python3 make g++

# Install pnpm globally and make it available for the full image lifetime
RUN npm install -g pnpm@10

WORKDIR /app

# Copy workspace config first for better layer caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY tsconfig.json tsconfig.base.json ./

# Copy library packages and the api-server artifact
COPY lib/ lib/
COPY artifacts/api-server/ artifacts/api-server/

# Install all dependencies (dev deps included — needed to build)
RUN pnpm install --frozen-lockfile

# Compile TypeScript → dist/ via esbuild
RUN pnpm --filter @workspace/api-server run build

ENV NODE_ENV=production

EXPOSE 8080

# Run node directly — migrations happen inside the process on startup
CMD ["node", "--enable-source-maps", "/app/artifacts/api-server/dist/index.mjs"]
