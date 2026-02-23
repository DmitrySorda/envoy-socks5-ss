/// @file config.cc
/// @brief Envoy SOCKS5 filter factory implementation

#include "socks5_filter.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/network/common/factory_base.h"

#include "proto/socks5_filter.pb.h"
#include "proto/socks5_filter.pb.validate.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace Socks5 {

constexpr char FilterName[] = "envoy.filters.network.socks5";

/// Factory for creating SOCKS5 filter instances
class Socks5FilterConfigFactory 
    : public Server::Configuration::NamedNetworkFilterConfigFactory {
public:
    std::string name() const override { return FilterName; }

    /// Create filter chain from proto config
    Network::FilterFactoryCb createFilterFactoryFromProto(
        const Protobuf::Message& proto_config,
        Server::Configuration::FactoryContext& context) override {
        
        const auto& config = 
            MessageUtil::downcastAndValidate<const socks5::v3::Socks5Filter&>(
                proto_config, context.messageValidationVisitor());
        
        return createFilterFactory(config, context);
    }

    /// Return the proto config descriptor
    ProtobufTypes::MessagePtr createEmptyConfigProto() override {
        return std::make_unique<socks5::v3::Socks5Filter>();
    }

private:
    Network::FilterFactoryCb createFilterFactory(
        const socks5::v3::Socks5Filter& proto_config,
        Server::Configuration::FactoryContext& context) {
        
        auto config = std::make_shared<Socks5FilterConfig>();
        config->stat_prefix = proto_config.stat_prefix();
        config->auth_required = proto_config.auth_required();
        
        return [config, &context](Network::FilterManager& filter_manager) -> void {
            filter_manager.addFilter(std::make_shared<Socks5Filter>(
                config, context.clusterManager()));
        };
    }
};

/// Register the filter factory with Envoy
LEGACY_REGISTER_FACTORY(Socks5FilterConfigFactory,
                        Server::Configuration::NamedNetworkFilterConfigFactory,
                        FilterName);

} // namespace Socks5
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
