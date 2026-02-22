workspace(name = "envoy_socks5_filter")

# =============================================================================
# Envoy Dependencies
# =============================================================================

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Envoy main repository
ENVOY_VERSION = "1.37.0"
ENVOY_SHA256 = ""  # Will be filled after release

http_archive(
    name = "envoy",
    sha256 = ENVOY_SHA256,
    strip_prefix = "envoy-" + ENVOY_VERSION,
    urls = ["https://github.com/envoyproxy/envoy/archive/refs/tags/v" + ENVOY_VERSION + ".tar.gz"],
)

# For local development, you can use local_repository instead:
# local_repository(
#     name = "envoy",
#     path = "/path/to/envoy",
# )

# =============================================================================
# Load Envoy dependencies
# =============================================================================

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")
envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")
envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")
envoy_dependencies()

load("@envoy//bazel:repositories_extra.bzl", "envoy_dependencies_extra")
envoy_dependencies_extra()

load("@envoy//bazel:python_dependencies.bzl", "envoy_python_dependencies")
envoy_python_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")
envoy_dependency_imports()

# =============================================================================
# OpenSSL for Shadowsocks crypto
# =============================================================================

# OpenSSL is already included via Envoy's BoringSSL, but we need full OpenSSL
# for some HKDF functions. This may need adjustment based on Envoy version.
