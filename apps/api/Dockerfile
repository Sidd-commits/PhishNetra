FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY packages/shared/package*.json ./packages/shared/
COPY apps/api/package*.json ./apps/api/
COPY prisma ./prisma

RUN npm install

COPY packages/shared ./packages/shared
COPY apps/api ./apps/api

RUN npm run build:shared
RUN cd apps/api && npm run prisma:generate && npm run build

FROM node:20-alpine AS runner

WORKDIR /app

COPY package*.json ./
COPY packages/shared/package*.json ./packages/shared/
COPY apps/api/package*.json ./apps/api/
COPY prisma ./prisma

RUN npm install --omit=dev

COPY --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

EXPOSE 5000

CMD ["node", "apps/api/dist/index.js"]
