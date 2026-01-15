

# STAGE 1: Build (The "Builder")
# Use the LTS version of Node.js on a lightweight Alpine Linux base
FROM node:20-alpine AS builder

# Create app directory
WORKDIR /app

# Copy package files first to leverage Docker's cache
# This ensures "npm install" only runs if your dependencies change
COPY package*.json ./

# Install ALL dependencies (including devDependencies for building)
RUN npm install

# Copy the rest of your source code
COPY . .

# Optional: Run a build script if you use TypeScript or a bundler (e.g., NestJS)
# RUN npm run build

# STAGE 2: Run (The "Production" Image)
FROM node:20-alpine AS runner

FROM node:20-alpine
# This removes the "New major version" notice
RUN npm install -g npm@latest

# Set environment to production
ENV NODE_ENV=production

WORKDIR /app

# Copy only the necessary files from the builder stage
# We copy node_modules and the built code (usually in /dist or just /.)
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app ./ 

# BACK4APP REQUIREMENT: Back4app uses the PORT environment variable.
# Ensure your code listens on process.env.PORT
ENV PORT=8080
EXPOSE 8080

# Security: Run as a non-root user (Alpine has a 'node' user built-in)
USER node

# Start the application
CMD ["node", "server.js"]
