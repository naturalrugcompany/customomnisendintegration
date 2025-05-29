FROM node:16-alpine

WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install all dependencies including dev dependencies needed for build
RUN npm ci

# Copy source code
COPY . .

# Build the app
RUN npm run build

# Start the app
CMD [ "npm", "start" ]
