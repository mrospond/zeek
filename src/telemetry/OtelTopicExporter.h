#pragma once

#include <string>
#include <vector>

#include "zeek/RE.h"
#include "zeek/Val.h"

#include "opentelemetry/sdk/metrics/push_metric_exporter.h"

namespace zeek::telemetry::detail {

class OtelTopicExporter final : public opentelemetry::sdk::metrics::PushMetricExporter {
public:
    OtelTopicExporter(const std::string& topic, const std::string& endpoint, const std::vector<std::string>& prefixes,
                      opentelemetry::sdk::metrics::AggregationTemporality aggregation_temporality =
                          opentelemetry::sdk::metrics::AggregationTemporality::kCumulative);

    ~OtelTopicExporter() override = default;

    /**
     * Export
     * @param data metrics data
     */
    opentelemetry::sdk::common::ExportResult Export(
        const opentelemetry::sdk::metrics::ResourceMetrics& data) noexcept override;

    /**
     * Get the AggregationTemporality for ostream exporter
     *
     * @return AggregationTemporality
     */
    opentelemetry::sdk::metrics::AggregationTemporality GetAggregationTemporality(
        opentelemetry::sdk::metrics::InstrumentType instrument_type) const noexcept override;

    /**
     * Force flush the exporter.
     */
    bool ForceFlush(std::chrono::microseconds timeout = (std::chrono::microseconds::max)()) noexcept override;

    /**
     * Shut down the exporter.
     * @param timeout an optional timeout.
     * @return return the status of this operation
     */
    bool Shutdown(std::chrono::microseconds timeout = (std::chrono::microseconds::max)()) noexcept override;

private:
    bool is_shutdown = false;
    std::string topic;
    std::string endpoint;
    std::vector<std::string> prefixes;
    opentelemetry::sdk::metrics::AggregationTemporality aggregation_temporality;

    std::map<std::string, RecordValPtr> records;

    zeek::RE_Matcher prefix_matcher;

    bool isShutdown() const noexcept;
};

} // namespace zeek::telemetry::detail
