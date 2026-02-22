load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_cc_extension",
    "envoy_extension_package",
)
load("@envoy_api//bazel:api_build_system.bzl", "api_proto_package")

licenses(["notice"])  # Apache 2

envoy_extension_package()

# =============================================================================
# Protocol Libraries (header-only)
# =============================================================================

envoy_cc_library(
    name = "socks5_lib",
    hdrs = ["include/socks5/socks5.hpp"],
    deps = [],
)

envoy_cc_library(
    name = "shadowsocks_lib",
    hdrs = [
        "include/shadowsocks/shadowsocks.hpp",
        "include/shadowsocks/ss_cluster.hpp",
    ],
    external_deps = ["ssl"],
    deps = [],
)

# =============================================================================
# Envoy Network Filter Extensions
# =============================================================================

# Original SOCKS5 filter (without SS encryption)
envoy_cc_extension(
    name = "socks5_config",
    srcs = [
        "src/filter/config.cc",
        "src/filter/socks5_filter.cc",
    ],
    hdrs = [
        "src/filter/socks5_filter.h",
    ],
    deps = [
        ":socks5_lib",
        ":socks5_proto_cc_proto",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//envoy/upstream:cluster_manager_interface",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/extensions/filters/network/common:factory_base_lib",
    ],
)

# SOCKS5 + Shadowsocks filter (with AEAD encryption and LB)
envoy_cc_extension(
    name = "socks5_ss_config",
    srcs = [
        "src/filter/ss_config.cc",
        "src/filter/ss_filter.cc",
    ],
    hdrs = [
        "src/filter/ss_filter.h",
    ],
    deps = [
        ":socks5_lib",
        ":shadowsocks_lib",
        ":socks5_ss_proto_cc_proto",
        "@envoy//envoy/event:dispatcher_interface",
        "@envoy//envoy/event:timer_interface",
        "@envoy//envoy/network:connection_interface",
        "@envoy//envoy/network:filter_interface",
        "@envoy//envoy/registry",
        "@envoy//envoy/server:filter_config_interface",
        "@envoy//envoy/stats:stats_interface",
        "@envoy//envoy/stats:stats_macros",
        "@envoy//source/common/buffer:buffer_lib",
        "@envoy//source/common/common:logger_lib",
        "@envoy//source/common/network:address_lib",
        "@envoy//source/common/network:utility_lib",
        "@envoy//source/extensions/filters/network/common:factory_base_lib",
    ],
)

# =============================================================================
# Proto Libraries
# =============================================================================

api_proto_package(
    name = "socks5_proto",
    srcs = ["proto/socks5_filter.proto"],
    deps = [
        "@com_github_cncf_udpa//udpa/annotations:pkg",
        "@envoy_api//envoy/annotations:pkg",
    ],
)

api_proto_package(
    name = "socks5_ss_proto",
    srcs = ["proto/socks5_ss.proto"],
    deps = [
        "@com_github_cncf_udpa//udpa/annotations:pkg",
        "@com_google_protobuf//:duration_proto",
    ],
)

# =============================================================================
# Tests
# =============================================================================

envoy_cc_test(
    name = "socks5_test",
    srcs = ["test/socks5_test.cc"],
    deps = [
        ":socks5_lib",
        "@com_google_googletest//:gtest_main",
    ],
)

envoy_cc_test(
    name = "shadowsocks_test",
    srcs = ["test/ss_test.cc"],
    deps = [
        ":shadowsocks_lib",
        "@com_google_googletest//:gtest_main",
    ],
)
