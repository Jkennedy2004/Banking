# Multi-stage build for security and efficiency
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Create non-root user for build
RUN addgroup -g 1001 -S nodejs && \
    adduser -S banking -u 1001

# Copy package files
COPY package*.json ./

# Install dependencies (including dev dependencies for build)
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Change ownership to non-root user
RUN chown -R banking:nodejs /app

# Production stage
FROM node:18-alpine AS production

# Install security updates
RUN apk --no-cache upgrade && \
    apk --no-cache add dumb-init && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S banking -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy production dependencies from builder
COPY --from=builder --chown=banking:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=banking:nodejs /app/package*.json ./

# Copy application code
COPY --chown=banking:nodejs src/ ./src/

# Create logs directory
RUN mkdir -p /app/logs && chown banking:nodejs /app/logs

# Remove unnecessary packages and files
RUN rm -rf /tmp/* /var/tmp/* /root/.npm

# Security hardening
RUN chmod -R 755 /app && \
    chmod -R 644 /app/src/*.js && \
    chmod +x /app/src/app.js

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV USER=banking

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Switch to non-root user
USER banking

# Expose port
EXPOSE 3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "src/app.js"]

# Metadata
LABEL maintainer="Banking Team <team@banking-app.com>"
LABEL version="1.0.0"
LABEL description="Secure Banking Application"
LABEL org.opencontainers.image.source="https://github.com/company/banking-app"
LABEL org.opencontainers.image.vendor="Banking Corp"
LABEL org.opencontainers.image.licenses="MIT"