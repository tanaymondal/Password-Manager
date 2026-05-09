FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -g 1000 -S securevault && \
    adduser -u 1000 -S securevault -G securevault

# Copy jar file
COPY target/securevault-1.0.0.jar app.jar

# Create logs directory
RUN mkdir -p /var/log/securevault && chown -R securevault:securevault /var/log/securevault

# Switch to non-root user
USER securevault

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

# Run application
ENTRYPOINT ["java", "-jar", "app.jar"]