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
# Stage 2: Runtime Stage
# =============================================================================
FROM amazoncorretto:21-alpine3.22

WORKDIR /app

COPY --from=builder /build/target/gillnet-ai-0.0.1-SNAPSHOT.jar /app/app.jar
COPY GillNet-AI-Backend/data /app/data

ENV PORT=8081
EXPOSE 8081

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-Xms64m", "-Xmx256m", "-XX:MaxMetaspaceSize=160m", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
