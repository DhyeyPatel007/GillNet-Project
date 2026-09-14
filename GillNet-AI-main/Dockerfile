# Production container for the GillNet SSR frontend on Render.
FROM oven/bun:1 AS builder

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build:render

FROM oven/bun:1-slim

WORKDIR /app
COPY --from=builder /app/.output ./.output

ENV NODE_ENV=production
EXPOSE 10000

# Nitro's node-server preset reads Render's PORT environment variable.
CMD ["bun", ".output/server/index.mjs"]
