# Dockerfile for Envoy with SOCKS5-SS filter
# 
# Build: docker build -t envoy-socks5-ss .
# Run:   docker run -p 1080:1080 -v ./keys.json:/etc/envoy/keys.json envoy-socks5-ss

# =============================================================================
# Stage 1: Build Envoy with extension (heavy, ~2GB)
# =============================================================================
FROM envoyproxy/envoy-build-ubuntu:latest AS builder

WORKDIR /build

# Copy extension source
COPY . /build/envoy-socks5-filter

# Clone Envoy
ARG ENVOY_VERSION=1.31.0
RUN git clone --depth 1 --branch v${ENVOY_VERSION} \
    https://github.com/envoyproxy/envoy.git /build/envoy

# Copy extension into Envoy source tree
RUN mkdir -p /build/envoy/source/extensions/filters/network/socks5_ss && \
    cp -r /build/envoy-socks5-filter/include/* \
          /build/envoy/source/extensions/filters/network/socks5_ss/ && \
    cp /build/envoy-socks5-filter/source/extensions/filters/network/socks5_ss/* \
       /build/envoy/source/extensions/filters/network/socks5_ss/ && \
    mkdir -p /build/envoy/api/envoy/extensions/filters/network/socks5_ss/v3 && \
    cp /build/envoy-socks5-filter/proto/socks5_ss.proto \
       /build/envoy/api/envoy/extensions/filters/network/socks5_ss/v3/

# Register extension
RUN echo '"envoy.filters.network.socks5_ss": "//source/extensions/filters/network/socks5_ss:config",' \
    >> /build/envoy/source/extensions/extensions_build_config.bzl

# Build Envoy
WORKDIR /build/envoy
RUN bazel build -c opt //source/exe:envoy-static

# =============================================================================
# Stage 2: Runtime image (minimal, ~50MB)
# =============================================================================
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Envoy binary
COPY --from=builder /build/envoy/bazel-bin/source/exe/envoy-static /usr/local/bin/envoy

# Copy default config
COPY examples/envoy-socks5-ss.yaml /etc/envoy/envoy.yaml

# Create non-root user
RUN useradd -m -s /bin/bash envoy
USER envoy

# SOCKS5 port
EXPOSE 1080
# Admin port
EXPOSE 9901

ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml", "--log-level", "info"]
