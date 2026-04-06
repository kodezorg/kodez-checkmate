FROM node:20-alpine

WORKDIR /app

# Install dependencies first (layer cache)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy application source
COPY . .

# Create local reports directory
RUN mkdir -p reports

EXPOSE 3000

CMD ["node", "server.js"]
