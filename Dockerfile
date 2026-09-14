# =============================================================================
# Stage 1: Build Stage (Maven + Eclipse Temurin OpenJDK 21)
# =============================================================================
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy backend pom.xml first to maximize Docker layer caching
COPY GillNet-AI-Backend/pom.xml .

# Download dependencies in an isolated layer
RUN mvn dependency:go-offline -B || true

# Copy backend source code
COPY GillNet-AI-Backend/src ./src

# Build production Spring Boot executable JAR without running test suites
RUN mvn clean package -DskipTests -B

# =============================================================================
# Stage 2: Runtime Stage (Lightweight Eclipse Temurin JRE 21)
# =============================================================================
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Ensure standard system paths find java
RUN ln -sf /opt/java/openjdk/bin/java /usr/bin/java && \
    ln -sf /opt/java/openjdk/bin/java /usr/local/bin/java

# Copy the executable Spring Boot fat JAR from builder stage
COPY --from=builder /build/target/gillnet-ai-0.0.1-SNAPSHOT.jar /app/app.jar
RUN cp /app/app.jar /app.jar

# Copy initial data store
COPY GillNet-AI-Backend/data ./data

# Copy entrypoint startup script
COPY GillNet-AI-Backend/entrypoint.sh /app/entrypoint.sh

# Ensure Unix LF line endings and executable permission
RUN sed -i 's/\r$//' /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh && \
    ln -sf /app/entrypoint.sh /entrypoint.sh

# Environment defaults (Render dynamically overrides $PORT)
ENV PORT=8081
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

# Document listening port
EXPOSE 8081

# Use entrypoint script with exec
ENTRYPOINT ["/app/entrypoint.sh"]
