#!/bin/sh

echo "=================================================="
echo "  GillNet AI Backend - Container Starting"
echo "  Port: ${PORT:-8081}"
echo "=================================================="

# Ensure data directory exists for file persistence
mkdir -p /app/data

# Verify application JAR exists
if [ ! -f /app/app.jar ]; then
    echo "WARNING: /app/app.jar not found! Checking fallback locations..."
    if [ -f /app.jar ]; then
        echo "Found /app.jar, copying to /app/app.jar..."
        cp /app.jar /app/app.jar
    elif [ -f /build/target/gillnet-ai-0.0.1-SNAPSHOT.jar ]; then
        echo "Found /build/target JAR, copying to /app/app.jar..."
        cp /build/target/gillnet-ai-0.0.1-SNAPSHOT.jar /app/app.jar
    else
        echo "FATAL: No executable JAR found in container!"
        ls -la /app
        exit 1
    fi
fi

# If command passed is 'java', delegate directly
if [ "$1" = "java" ]; then
    shift
    echo "==> Executing custom java command: java $@"
    exec java "$@"
fi

# If command passed is 'sh' or 'bash', delegate directly
if [ "$1" = "sh" ] || [ "$1" = "bash" ]; then
    echo "==> Executing shell command: $@"
    exec "$@"
fi

# Execute Spring Boot application as PID 1
echo "==> Launching GillNet AI Spring Boot Application..."
exec java \
  -XX:+UseContainerSupport \
  -XX:MaxRAMPercentage=75.0 \
  -Xmx384m \
  -Xss512k \
  -Djava.security.egd=file:/dev/./urandom \
  -Dserver.port="${PORT:-8081}" \
  -jar /app/app.jar \
  "$@"
