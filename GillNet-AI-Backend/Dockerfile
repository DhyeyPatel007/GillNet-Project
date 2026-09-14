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
# Stage 2: Runtime Stage
# =============================================================================
# Amazon Corretto has no inherited container entrypoint.  This matters on Render:
# the Eclipse Temurin JRE image's certificate wrapper never reached this
# application's entrypoint and Render reported only its opaque exit status 128.
FROM amazoncorretto:21-alpine3.22

WORKDIR /app

# Copy only production inputs. Keep data under the working directory because the
# file-backed fallback is used whenever MongoDB is unavailable.
COPY --from=builder /build/target/gillnet-ai-0.0.1-SNAPSHOT.jar /app/app.jar
COPY data /app/data

# Render discovers the listening socket automatically. The application also
# honors a Render-provided PORT through application.properties.
ENV PORT=8081
EXPOSE 8081

# Do not use a shell wrapper or inherited CMD: Java is PID 1 and receives all
# lifecycle signals directly. The conservative heap cap fits Render's free plan.
ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-Xms64m", "-Xmx256m", "-XX:MaxMetaspaceSize=160m", "-Djava.security.egd=file:/dev/./urandom", "-jar", "/app/app.jar"]
