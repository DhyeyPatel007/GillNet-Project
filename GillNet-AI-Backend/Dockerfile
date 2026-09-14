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

# Create a non-root system user for container security
RUN groupadd -r gillnet && useradd -r -g gillnet -m -s /bin/bash gillnet

# Copy the executable Spring Boot fat JAR from the builder stage
COPY --from=builder --chown=gillnet:gillnet /build/target/*.jar app.jar

# Switch to non-root user
USER gillnet

# Default port configuration (Render dynamically sets $PORT in runtime)
ENV PORT=8081
ENV JAVA_OPTS="-XX:+UseContainerSupport -XX:MaxRAMPercentage=75.0 -Djava.security.egd=file:/dev/./urandom"

# Document listening port
EXPOSE 8081

# Launch Spring Boot with dynamic port binding to Render's $PORT
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=${PORT} -jar app.jar"]
