FROM node:20-alpine AS deps

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1

RUN addgroup -S nextjs && adduser -S nextjs -G nextjs
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder --chown=nextjs:nextjs /app/.next ./.next
COPY --from=builder --chown=nextjs:nextjs /app/next.config.mjs ./next.config.mjs
COPY --from=builder --chown=nextjs:nextjs /app/app ./app
COPY --from=builder --chown=nextjs:nextjs /app/components ./components
COPY --from=builder --chown=nextjs:nextjs /app/lib ./lib
COPY --from=builder --chown=nextjs:nextjs /app/tailwind.config.ts ./tailwind.config.ts
COPY --from=builder --chown=nextjs:nextjs /app/postcss.config.mjs ./postcss.config.mjs

USER nextjs

CMD ["npm", "run", "start"]
