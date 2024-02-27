#include "OtelTopicExporter.h"

#include "zeek/RunState.h"
#include "zeek/broker/Data.h"
#include "zeek/broker/Manager.h"
#include "zeek/telemetry/Manager.h"

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

    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto metric_vector_type = zeek::id::find_type<zeek::VectorType>("Telemetry::MetricVector");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto labels_idx = metric_record_type->FieldOffset("labels");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto count_value_idx = metric_record_type->FieldOffset("count_value");
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("any_vec");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");

    for ( auto& instrumentation_info : data.scope_metric_data_ ) {
        for ( const auto& metric : instrumentation_info.metric_data_ ) {
            if ( ! prefixes.empty() ) {
                int res = prefix_matcher.MatchPrefix(metric.instrument_descriptor.name_.c_str());
                if ( res == -1 )
                    continue;
            }

            auto family = telemetry_mgr->GetFamilyByFullName(metric.instrument_descriptor.name_);
            if ( ! family )
                continue;

            auto counter_vec = make_intrusive<VectorVal>(metric_vector_type);
            auto gauge_vec = make_intrusive<VectorVal>(metric_vector_type);

            switch ( family->MetricType() ) {
                case BifEnum::Telemetry::MetricType::INT_COUNTER: {
                    auto counters = static_cast<IntCounterFamily*>(family.get())->GetAllCounters();
                    for ( const auto& c : counters ) {
                        if ( auto change = c->Change(); change != 0 ) {
                            RecordValPtr record = make_intrusive<RecordVal>(metric_record_type);
                            record->Assign(opts_idx, family->GetMetricOptsRecord());
                            record->Assign(count_value_idx, change);

                            VectorValPtr labels = make_intrusive<VectorVal>(string_vec_type);
                            auto label_values = c->LabelValues();
                            for ( const auto& v : label_values )
                                labels->Append(make_intrusive<StringVal>(v));

                            record->Assign(labels_idx, labels);
                            counter_vec->Append(record);
                        }
                    }
                    break;
                }
                case BifEnum::Telemetry::MetricType::DOUBLE_COUNTER: {
                    const auto& counters = static_cast<DblCounterFamily*>(family.get())->GetAllCounters();
                    for ( const auto& c : counters ) {
                        if ( auto change = c->Change(); change != 0 ) {
                            RecordValPtr record = make_intrusive<RecordVal>(metric_record_type);
                            record->Assign(opts_idx, family->GetMetricOptsRecord());
                            record->Assign(value_idx, change);

                            VectorValPtr labels = make_intrusive<VectorVal>(string_vec_type);
                            auto label_values = c->LabelValues();
                            for ( const auto& v : label_values )
                                labels->Append(make_intrusive<StringVal>(v));

                            record->Assign(labels_idx, labels);
                            counter_vec->Append(record);
                        }
                    }
                    break;
                }
                case BifEnum::Telemetry::MetricType::INT_GAUGE: {
                    const auto& gauges = static_cast<IntGaugeFamily*>(family.get())->GetAllGauges();
                    for ( const auto& g : gauges ) {
                        if ( auto change = g->Change(); change != 0 ) {
                            RecordValPtr record = make_intrusive<RecordVal>(metric_record_type);
                            record->Assign(opts_idx, family->GetMetricOptsRecord());
                            record->Assign(value_idx, change);

                            VectorValPtr labels = make_intrusive<VectorVal>(string_vec_type);
                            auto label_values = g->LabelValues();
                            for ( const auto& v : label_values )
                                labels->Append(make_intrusive<StringVal>(v));

                            record->Assign(labels_idx, labels);
                            gauge_vec->Append(record);
                        }
                    }
                    break;
                }
                case BifEnum::Telemetry::MetricType::DOUBLE_GAUGE: {
                    const auto& gauges = static_cast<DblGaugeFamily*>(family.get())->GetAllGauges();
                    for ( const auto& g : gauges ) {
                        if ( auto change = g->Change(); change != 0 ) {
                            RecordValPtr record = make_intrusive<RecordVal>(metric_record_type);
                            record->Assign(opts_idx, family->GetMetricOptsRecord());
                            record->Assign(value_idx, change);

                            VectorValPtr labels = make_intrusive<VectorVal>(string_vec_type);
                            auto label_values = g->LabelValues();
                            for ( const auto& v : label_values )
                                labels->Append(make_intrusive<StringVal>(v));

                            record->Assign(labels_idx, labels);
                            gauge_vec->Append(record);
                        }
                    }
                    break;
                }
                case BifEnum::Telemetry::MetricType::INT_HISTOGRAM: break;
                case BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM: break;
                default: break;
            }

            if ( ! run_state::terminating ) {
                if ( counter_vec->Size() > 0 ) {
                    printf("sending %d counter events\n", counter_vec->Size());
                    BrokerListBuilder arg_list;
                    arg_list.Add(counter_vec);
                    auto ev_args = std::move(arg_list).Build();
                    broker_mgr->PublishEvent(topic, "update_remote_telemetry_counters", std::move(ev_args),
                                             util::current_time());
                }

                if ( gauge_vec->Size() > 0 ) {
                    printf("sending %d gauge events\n", gauge_vec->Size());
                    BrokerListBuilder arg_list;
                    arg_list.Add(gauge_vec);
                    auto ev_args = std::move(arg_list).Build();
                    broker_mgr->PublishEvent(topic, "telemetry_update_remote_gauges", std::move(ev_args),
                                             util::current_time());
                }
            }
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
