# ---- Build Stage ----
FROM node:22-alpine AS builder

WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN if [ -f package-lock.json ]; then \
    npm ci; \
    else \
    npm install; \
    fi

# Copiar código fuente
COPY . .

# Generar Prisma client y construir
RUN npx prisma generate && npm run build

# Verify build output exists (debugging step)
RUN ls -la /app/dist || echo "Build failed - no dist directory"

# ---- Production Stage ----
FROM node:22-alpine

WORKDIR /app

# Instalar curl para healthchecks
RUN apk --no-cache add curl

# Copiar archivos necesarios para runtime
COPY package*.json ./
COPY prisma ./prisma/

# Instalar solo dependencias de producción y generar cliente de Prisma
RUN if [ -f package-lock.json ]; then \
    npm ci --omit=dev; \
    else \
    npm install --omit=dev; \
    fi && \
    npx prisma generate

# Copiar la app compilada desde builder
COPY --from=builder /app/dist ./dist

# Verify the copy worked
RUN ls -la /app/dist || echo "Copy failed - no dist directory"

# Crear usuario no-root por seguridad
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3000

CMD ["node", "dist/src/main.js"]
