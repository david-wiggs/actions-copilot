# Simple Dockerfile for Actions Copilot
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Expose port (configurable via PORT env var, defaults to 3000)
EXPOSE ${PORT:-3000}

# Start the application
CMD ["npm", "start"]
