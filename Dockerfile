FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./

# Use npm ci for clean installs (avoids symlink issues)
RUN npm ci --only=production

COPY server.js ./

# STAGE 2
FROM node:20-alpine

ENV NODE_ENV=production
ENV PORT=8080

WORKDIR /app

COPY --from=builder /app ./

EXPOSE 8080

USER node

CMD ["node", "server.js"]
