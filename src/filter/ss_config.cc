/// @file ss_config.cc
/// @brief Envoy SOCKS5-SS filter factory

#include "src/filter/ss_filter.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/common/factory_base.h"

#include "proto/socks5_ss.pb.h"
#include "proto/socks5_ss.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5Ss {

constexpr char FilterName[] = "envoy.filters.network.socks5_ss";

/// Factory for creating SOCKS5-SS filter instances
class SsFilterConfigFactory 
    : public Server::Configuration::NamedNetworkFilterConfigFactory {
public:
    std::string name() const override { return FilterName; }

    Network::FilterFactoryCb createFilterFactoryFromProto(
        const Protobuf::Message& proto_config,
        Server::Configuration::FactoryContext& context) override {
        
        const auto& config = 
            MessageUtil::downcastAndValidate<const socks5_ss::v3::Socks5SsFilter&>(
                proto_config, context.messageValidationVisitor());
        
        auto filter_config = std::make_shared<SsFilterConfig>();
        filter_config->stat_prefix = config.stat_prefix();
        filter_config->auth_required = config.auth_required();
        filter_config->servers_config_path = config.servers_config_path();
        
        // Parse LB policy
        switch (config.lb_policy()) {
            case socks5_ss::v3::ROUND_ROBIN:
                filter_config->lb_policy = shadowsocks::LbPolicy::RoundRobin;
                break;
            case socks5_ss::v3::LEAST_CONNECTIONS:
                filter_config->lb_policy = shadowsocks::LbPolicy::LeastConnections;
                break;
            case socks5_ss::v3::RANDOM:
                filter_config->lb_policy = shadowsocks::LbPolicy::Random;
                break;
            case socks5_ss::v3::WEIGHTED_LATENCY:
            default:
                filter_config->lb_policy = shadowsocks::LbPolicy::WeightedLatency;
                break;
        }
        
        // Parse intervals
        if (config.has_health_check_interval()) {
            filter_config->health_check_interval = std::chrono::seconds(
                config.health_check_interval().seconds());
        }
        
        if (config.has_config_reload_interval()) {
            filter_config->config_reload_interval = std::chrono::seconds(
                config.config_reload_interval().seconds());
        }
        
        // Create stats
        filter_config->stats = std::make_shared<SsFilterStats>(
            generateStats(filter_config->stat_prefix + ".", context.scope()));
        
        // Create cluster
        shadowsocks::Cluster::Config cluster_config;
        cluster_config.lb_policy = filter_config->lb_policy;
        cluster_config.health_check_interval = filter_config->health_check_interval;
        filter_config->cluster = std::make_shared<shadowsocks::Cluster>(cluster_config);
        
        // Create config manager for hot reload
        auto config_manager = std::make_shared<ConfigManager>(
            context.mainThreadDispatcher(),
            filter_config,
            filter_config->servers_config_path);
        
        return [filter_config, config_manager](Network::FilterManager& filter_manager) -> void {
            filter_manager.addFilter(std::make_shared<SsFilter>(filter_config));
        };
    }

    ProtobufTypes::MessagePtr createEmptyConfigProto() override {
        return std::make_unique<socks5_ss::v3::Socks5SsFilter>();
    }
};

LEGACY_REGISTER_FACTORY(SsFilterConfigFactory,
                        Server::Configuration::NamedNetworkFilterConfigFactory,
                        FilterName);

} // namespace Socks5Ss
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
