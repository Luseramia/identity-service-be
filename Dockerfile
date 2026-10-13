FROM oven/bun:1.2.14 AS dependencies
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

FROM oven/bun:1.2.14
WORKDIR /app
ENV NODE_ENV=production
COPY --from=dependencies /app/node_modules ./node_modules
COPY src ./src
COPY migrations ./migrations
COPY scripts ./scripts
COPY package.json ./
USER bun
EXPOSE 3001/tcp
CMD ["bun", "src/index.ts"]
