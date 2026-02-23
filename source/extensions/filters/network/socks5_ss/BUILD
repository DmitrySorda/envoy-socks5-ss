load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "socks5_lib",
    hdrs = ["socks5/socks5.hpp"],
    deps = [],
)

envoy_cc_library(
    name = "shadowsocks_lib",
    hdrs = [
        "shadowsocks/shadowsocks.hpp",
        "shadowsocks/ss_cluster.hpp",
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
        "@envoy_api//envoy/extensions/filters/network/socks5_ss/v3:pkg_cc_proto",
        "//envoy/event:dispatcher_interface",
        "//envoy/event:timer_interface",
        "//envoy/network:connection_interface",
        "//envoy/network:filter_interface",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//envoy/stats:stats_interface",
        "//envoy/stats:stats_macros",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/common/network:address_lib",
        "//source/common/network:utility_lib",
        "//source/extensions/filters/network/common:factory_base_lib",
    ],
)
