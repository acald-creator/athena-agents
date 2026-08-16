# =============================================================================
# Athena Agents - Multi-Stage Docker Build
# Produces a minimal agent runner image with Rust binaries + Python orchestrator
# No build-time toolchains in the final image.
#
# SecurityContext annotations (for Kubernetes):
#   - Drop ALL capabilities
#   - allowPrivilegeEscalation: false
#   - No Docker socket or hostPath mounts
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: rust-builder
# Compile Rust binaries as statically-linked musl binaries
# ---------------------------------------------------------------------------
FROM rust:1.78-alpine AS rust-builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static

WORKDIR /app

# Cache dependency layer: copy workspace Cargo manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/athena-common/Cargo.toml crates/athena-common/Cargo.toml
COPY crates/athena-scanner/Cargo.toml crates/athena-scanner/Cargo.toml
COPY crates/athena-fuzzer/Cargo.toml crates/athena-fuzzer/Cargo.toml
COPY crates/athena-crafter/Cargo.toml crates/athena-crafter/Cargo.toml

# Create dummy source files to seed the dependency cache
RUN mkdir -p crates/athena-common/src && echo "// placeholder" > crates/athena-common/src/lib.rs \
    && mkdir -p crates/athena-scanner/src && echo "fn main() {}" > crates/athena-scanner/src/main.rs \
    && mkdir -p crates/athena-fuzzer/src && echo "fn main() {}" > crates/athena-fuzzer/src/main.rs \
    && mkdir -p crates/athena-crafter/src && echo "fn main() {}" > crates/athena-crafter/src/main.rs

# Build dependencies only (cache layer)
RUN cargo build --release --target x86_64-unknown-linux-musl 2>/dev/null || true

# Copy real source code
COPY crates/ crates/

# Touch source files to invalidate the dummy builds
RUN find crates -name "*.rs" -exec touch {} +

# Build release binaries (static musl)
RUN cargo build --release --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/athena-scanner /usr/local/bin/ 2>/dev/null || true \
    && cp target/x86_64-unknown-linux-musl/release/athena-fuzzer /usr/local/bin/ 2>/dev/null || true \
    && cp target/x86_64-unknown-linux-musl/release/athena-crafter /usr/local/bin/ 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2: python-env
# Install the Python orchestrator package into a portable prefix
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS python-env

WORKDIR /app

# Install build dependencies for Python packages
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy Python project files
COPY pyproject.toml ./
COPY orchestrator/ orchestrator/
COPY eval/ eval/

# Install the package into a dedicated prefix for clean COPY in final stage
RUN pip install --no-cache-dir --prefix=/install .

# ---------------------------------------------------------------------------
# Stage 3: runner
# Final minimal image - no build toolchains
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runner

# OCI labels documenting security context requirements
LABEL org.opencontainers.image.title="athena-agents"
LABEL org.opencontainers.image.description="AI offensive agent framework for autonomous security testing"
LABEL org.opencontainers.image.vendor="PhoenixVLabs"
LABEL io.kubernetes.security.drop-capabilities="ALL"
LABEL io.kubernetes.security.allow-privilege-escalation="false"
LABEL io.kubernetes.security.run-as-non-root="true"
LABEL io.kubernetes.security.no-docker-socket="true"
LABEL io.kubernetes.security.no-host-path-volumes="true"

# Create non-root user (UID 1000)
RUN groupadd --gid 1000 athena \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/sh athena

# Copy statically-linked Rust binaries from builder
COPY --from=rust-builder /usr/local/bin/athena-scanner /usr/local/bin/
COPY --from=rust-builder /usr/local/bin/athena-fuzzer /usr/local/bin/
COPY --from=rust-builder /usr/local/bin/athena-crafter /usr/local/bin/

# Copy Python environment from python-env stage
COPY --from=python-env /install /usr/local

# Copy application source (orchestrator + eval modules)
COPY orchestrator/ /app/orchestrator/
COPY eval/ /app/eval/

# Copy configuration directory
COPY config/ /app/config/

# Set environment variables
ENV ATHENA_BIN_DIR=/usr/local/bin
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

# Switch to non-root user
USER athena

# Default entrypoint: Python orchestrator
ENTRYPOINT ["python3", "-m", "orchestrator"]
