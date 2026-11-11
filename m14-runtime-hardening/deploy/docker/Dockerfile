# Reference image: multi-stage build, minimal runtime, non-root user, no shell, no toolchain.
# Build from the repository root so layer caching matches the reactor output:
#   DOCKER_BUILDKIT=1 docker build -f m14-runtime-hardening/deploy/docker/Dockerfile \
#       -t registry.example.org/espd/m14-runtime-hardening:1.0.0 .
FROM eclipse-temurin:21-jdk AS builder
WORKDIR /build
COPY . .
RUN ./mvnw -q -DskipTests -pl m14-runtime-hardening -am package \
    && cp m14-runtime-hardening/target/*.jar /build/app.jar

# jre-alpine keeps the image small; distroless/java21 is the better choice where the registry has it
# (no shell at all, which is what removes the post-exploitation toolkit).
FROM eclipse-temurin:21-jre-alpine AS runtime
RUN addgroup -S -g 10001 app && adduser -S -u 10001 -G app app
WORKDIR /app
COPY --from=builder --chown=10001:10001 /build/app.jar /app/app.jar
USER 10001:10001
EXPOSE 8094
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError"
HEALTHCHECK --interval=30s --timeout=3s CMD ["sh", "-c", "exit 0"]
# Exec form (no shell wrapper), read-only rootfs compatible, writes only to /tmp (mounted tmpfs).
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
