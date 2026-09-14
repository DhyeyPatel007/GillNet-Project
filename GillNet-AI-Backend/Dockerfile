# =============================================================================
# Stage 1: Build Stage (Maven + Eclipse Temurin OpenJDK 21)
# =============================================================================
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy pom.xml first to maximize Docker layer caching
COPY pom.xml .

# Download dependencies in an isolated layer
RUN mvn dependency:go-offline -B || true

# Copy project source code
COPY src ./src

# Build production Spring Boot executable JAR without running test suites
RUN mvn clean package -DskipTests -B

# =============================================================================
# Stage 2: Runtime Stage (Lightweight Eclipse Temurin JRE 21)
# =============================================================================
FROM eclipse-temurin:21-jre-jammy

WORKDIR /app

# Copy the executable Spring Boot fat JAR from the builder stage
COPY --from=builder /build/target/*.jar /app/app.jar

# JVM automatically picks up JAVA_TOOL_OPTIONS without needing shell expansion
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"
ENV PORT=8081

# Document listening port
EXPOSE 8081

# Render executes the CMD instruction by default; use absolute path to JAR
CMD ["java", "-jar", "/app/app.jar"]
