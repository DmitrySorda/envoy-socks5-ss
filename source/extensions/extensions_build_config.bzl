# Extension registration for Envoy build system
# This file tells Envoy which extensions to include in the build

EXTENSIONS = {
    # SOCKS5 + Shadowsocks Network Filter
    "envoy.filters.network.socks5_ss": "//source/extensions/filters/network/socks5_ss:config",
    
    # Plain SOCKS5 filter (without SS encryption)
    "envoy.filters.network.socks5": "//source/extensions/filters/network/socks5:config",
}

# Disabled extensions (for minimal build)
DISABLED_BY_DEFAULT = []

# Extension categories
EXTENSION_CATEGORIES = {
    "network_filter": [
        "envoy.filters.network.socks5_ss",
        "envoy.filters.network.socks5",
    ],
}
