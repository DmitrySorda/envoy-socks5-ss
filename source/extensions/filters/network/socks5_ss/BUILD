load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "socks5_lib",
    hdrs = ["//include/socks5:socks5.hpp"],
    deps = [],
)

envoy_cc_library(
    name = "shadowsocks_lib",
    hdrs = [
        "//include/shadowsocks:shadowsocks.hpp",
        "//include/shadowsocks:ss_cluster.hpp",
    ],
    external_deps = ["ssl"],
    deps = [],
)

envoy_cc_extension(
    name = "config",
    srcs = [
        "ss_config.cc",
        "ss_filter.cc",
    ],
    hdrs = [
        "ss_filter.h",
    ],
    deps = [
        ":socks5_lib",
        ":shadowsocks_lib",
        "//proto:socks5_ss_cc_proto",
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
