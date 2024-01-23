#include "OtelTopicExporter.h"

#include "opentelemetry/sdk/metrics/export/metric_producer.h"

namespace zeek::telemetry::detail {

OtelTopicExporter::OtelTopicExporter(const std::string& topic, const std::string& endpoint,
                                     const std::vector<std::string>& prefixes,
                                     opentelemetry::sdk::metrics::AggregationTemporality aggregation_temporality)
    : topic(topic), endpoint(endpoint), prefixes(prefixes), aggregation_temporality(aggregation_temporality) {
    for ( const auto& prefix : prefixes ) {
        prefix_matcher.AddPat(prefix.c_str());
    }
}

/**
 * Export
 * @param data metrics data
 */
opentelemetry::sdk::common::ExportResult OtelTopicExporter::Export(
    const opentelemetry::sdk::metrics::ResourceMetrics& data) noexcept {
    if ( isShutdown() )
        return opentelemetry::sdk::common::ExportResult::kFailure;

    for ( auto& record : data.scope_metric_data_ ) {
        for ( const auto& metric : record.metric_data_ ) {
            int res = prefix_matcher.MatchPrefix(metric.instrument_descriptor.name_.c_str());
            if ( res == -1 )
                continue;
        }
    }

    return opentelemetry::sdk::common::ExportResult::kSuccess;
}

/**
 * Get the AggregationTemporality for ostream exporter
 *
 * @return AggregationTemporality
 */
opentelemetry::sdk::metrics::AggregationTemporality OtelTopicExporter::GetAggregationTemporality(
    opentelemetry::sdk::metrics::InstrumentType instrument_type) const noexcept {
    return aggregation_temporality;
}

/**
 * Force flush the exporter.
 */
bool OtelTopicExporter::ForceFlush(std::chrono::microseconds timeout) noexcept { return true; }

/**
 * Shut down the exporter.
 * @param timeout an optional timeout.
 * @return return the status of this operation
 */
bool OtelTopicExporter::Shutdown(std::chrono::microseconds timeout) noexcept {
    is_shutdown = true;
    return true;
}

bool OtelTopicExporter::isShutdown() const noexcept { return is_shutdown; }

} // namespace zeek::telemetry::detail
