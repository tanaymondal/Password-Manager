# Build stage
FROM maven:3-eclipse-temurin-17 AS build
WORKDIR /app
ARG CACHEBUST=1
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests -q

# Runtime stage
FROM eclipse-temurin:17-jre
WORKDIR /app

RUN groupadd -g 1001 securevault && \
    useradd -u 1001 -g securevault -s /sbin/nologin -M securevault

COPY --from=build /app/target/securevault-1.0.0.jar app.jar

RUN mkdir -p /var/log/securevault && chown -R securevault:securevault /var/log/securevault

USER securevault
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]