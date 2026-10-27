# ===================================================
# Stage 1: Build Frontend Assets
# ===================================================
FROM node:20-alpine AS client-builder
WORKDIR /app/client

COPY client/package*.json ./
RUN npm ci

COPY client/ ./
RUN npm run build

# ===================================================
# Stage 2: Production Server & Runner
# ===================================================
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=5001

# Install git (required by repositoryService for cloning public GitHub repos)
RUN apk add --no-cache git

# Install server production dependencies
WORKDIR /app/server
COPY server/package*.json ./
RUN npm ci --omit=dev

COPY server/ ./

# Copy built frontend assets from client-builder
COPY --from=client-builder /app/client/dist /app/client/dist

# Security: Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 5001

CMD ["node", "src/server.js"]
