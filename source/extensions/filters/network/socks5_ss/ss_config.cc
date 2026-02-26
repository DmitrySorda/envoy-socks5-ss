/**
 * @file ss_config.cc
 * @brief Factory registration for the SOCKS5-SS network filter.
 */

#include "source/extensions/filters/network/socks5_ss/ss_filter.h"

#include "envoy/extensions/filters/network/socks5_ss/v3/socks5_ss.pb.h"
#include "envoy/extensions/filters/network/socks5_ss/v3/socks5_ss.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5Ss {

constexpr char FilterName[] = "envoy.filters.network.socks5_ss";

/**
 * Config factory for the SOCKS5-SS filter.
 *
 * Extends Common::FactoryBase to get automatic proto de-serialisation,
 * name(), and createEmptyConfigProto() for free.
 */
class SsFilterConfigFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::network::socks5_ss::v3::Socks5SsFilter> {
public:
  SsFilterConfigFactory() : FactoryBase(FilterName) {}

private:
  Network::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::network::socks5_ss::v3::Socks5SsFilter&
          proto_config,
      Server::Configuration::FactoryContext& context) override {

    auto filter_config = std::make_shared<SsFilterConfig>();
    filter_config->stat_prefix = proto_config.stat_prefix();
    filter_config->auth_required = proto_config.auth_required();
    filter_config->servers_config_path = proto_config.servers_config_path();

    // LB policy.
    switch (proto_config.lb_policy()) {
    case envoy::extensions::filters::network::socks5_ss::v3::ROUND_ROBIN:
      filter_config->lb_policy = shadowsocks::LbPolicy::RoundRobin;
      break;
    case envoy::extensions::filters::network::socks5_ss::v3::LEAST_CONNECTIONS:
      filter_config->lb_policy = shadowsocks::LbPolicy::LeastConnections;
      break;
    case envoy::extensions::filters::network::socks5_ss::v3::RANDOM:
      filter_config->lb_policy = shadowsocks::LbPolicy::Random;
      break;
    case envoy::extensions::filters::network::socks5_ss::v3::WEIGHTED_LATENCY:
    default:
      filter_config->lb_policy = shadowsocks::LbPolicy::WeightedLatency;
      break;
    }

    // Duration fields.
    if (proto_config.has_health_check_interval()) {
      filter_config->health_check_interval =
          std::chrono::seconds(proto_config.health_check_interval().seconds());
    }
    if (proto_config.has_config_reload_interval()) {
      filter_config->config_reload_interval =
          std::chrono::seconds(proto_config.config_reload_interval().seconds());
    }

    // Retry / circuit-breaker knobs.
    if (proto_config.max_retries() > 0) {
      filter_config->max_retries = proto_config.max_retries();
    }
    filter_config->max_connections_per_server =
        proto_config.max_connections_per_server();

    // Stats.
    filter_config->stats = std::make_shared<SsFilterStats>(
        generateStats(filter_config->stat_prefix + ".", context.scope()));

    // Cluster.
    shadowsocks::Cluster::Config cluster_config;
    cluster_config.lb_policy = filter_config->lb_policy;
    cluster_config.health_check_interval =
        filter_config->health_check_interval;
    cluster_config.max_connections_per_server =
        filter_config->max_connections_per_server;
    filter_config->cluster =
        std::make_shared<shadowsocks::Cluster>(cluster_config);

    // Config manager owns the hot-reload timer and async health checks.
    auto config_manager = std::make_shared<ConfigManager>(
        context.serverFactoryContext().mainThreadDispatcher(), filter_config,
        filter_config->servers_config_path);

    return [filter_config,
            config_manager](Network::FilterManager& filter_manager) -> void {
      filter_manager.addReadFilter(
          std::make_shared<SsFilter>(filter_config));
    };
  }

  bool isTerminalFilterByProtoTyped(
      const envoy::extensions::filters::network::socks5_ss::v3::Socks5SsFilter&,
      Server::Configuration::ServerFactoryContext&) override {
    return true;
  }
};

/**
 * Static registration. The third argument is the deprecated name that older
 * configs may still reference.
 */
LEGACY_REGISTER_FACTORY(SsFilterConfigFactory,
                        Server::Configuration::NamedNetworkFilterConfigFactory,
                        "envoy.socks5_ss");

} // namespace Socks5Ss
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
