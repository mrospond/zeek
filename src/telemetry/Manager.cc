// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <algorithm>
#include <thread>
#include <variant>

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/ZeekString.h"
#include "zeek/broker/Manager.h"
#include "zeek/telemetry/ProcessStats.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/threading/formatters/detail/json.h"

#include "CivetServer.h"

namespace zeek::telemetry {

Manager::Manager() { prometheus_registry = std::make_shared<prometheus::Registry>(); }

Manager::~Manager() {}

void Manager::InitPostScript() {
    // Metrics port setting is used to calculate a URL for prometheus scraping
    std::string prometheus_url;
    if ( auto env = getenv("ZEEK_METRICS_PORT") )
        prometheus_url = util::fmt("localhost:%s", env);
    else {
        auto metrics_port = id::find_val("Telemetry::metrics_port")->AsPortVal();
        if ( metrics_port->Port() != 0 )
            prometheus_url = util::fmt("localhost:%u", metrics_port->Port());
    }

    if ( ! prometheus_url.empty() ) {
        CivetCallbacks* callbacks = nullptr;
        auto local_node_name = id::find_val("Cluster::node")->AsStringVal();
        if ( local_node_name->Len() > 0 ) {
            auto cluster_nodes = id::find_val("Cluster::nodes")->AsTableVal();
            auto local_node = cluster_nodes->Find(IntrusivePtr<StringVal>{NewRef{}, local_node_name});
            auto local_node_type = local_node->AsRecordVal()->GetField<EnumVal>("node_type")->Get();

            // TODO: the cluster node types aren't defined in a bif anywhere so we can't
            // just use a BifEnum for comparison here.
            if ( local_node_type == 3 ) {
                callbacks = new CivetCallbacks();
                callbacks->begin_request = [](struct mg_connection* conn) -> int {
                    // Handle the services.json request ourselves by building up a response based on
                    // the cluster configuration.
                    auto req_info = mg_get_request_info(conn);
                    if ( strcmp(req_info->request_uri, "/services.json") == 0 ) {
                        // send a request to a topic for data from workers
                        auto json = telemetry_mgr->GetClusterJson();
                        mg_send_http_ok(conn, "application/json", static_cast<long long>(json.size()));
                        mg_write(conn, json.data(), json.size());
                        return 1;
                    }

                    return 0;
                };
            }
        }

        try {
            prometheus_exposer = std::make_unique<prometheus::Exposer>(prometheus_url, 2, callbacks);
        } catch ( const CivetException& exc ) {
            reporter->FatalError("Failed to setup Prometheus endpoint: %s\n", exc.what());
        }

        prometheus_exposer->RegisterCollectable(prometheus_registry);
    }

#ifdef HAVE_PROCESS_STAT_METRICS
    static auto get_stats = [this]() -> const detail::process_stats* {
        double now = util::current_time();
        if ( this->process_stats_last_updated < now - 0.01 ) {
            this->current_process_stats = detail::get_process_stats();
            this->process_stats_last_updated = now;
        }

        return &this->current_process_stats;
    };
    rss_gauge = GaugeInstance<int64_t>("process", "resident_memory", {}, "Resident memory size", "bytes", false,
                                       []() -> prometheus::ClientMetric {
                                           auto* s = get_stats();
                                           prometheus::ClientMetric metric;
                                           metric.gauge.value = static_cast<double>(s->rss);
                                           return metric;
                                       });

    vms_gauge = GaugeInstance<int64_t>("process", "virtual_memory", {}, "Virtual memory size", "bytes", false,
                                       []() -> prometheus::ClientMetric {
                                           auto* s = get_stats();
                                           prometheus::ClientMetric metric;
                                           metric.gauge.value = static_cast<double>(s->vms);
                                           return metric;
                                       });

    cpu_gauge = GaugeInstance<double>("process", "cpu", {}, "Total user and system CPU time spent", "seconds", false,
                                      []() -> prometheus::ClientMetric {
                                          auto* s = get_stats();
                                          prometheus::ClientMetric metric;
                                          metric.gauge.value = s->cpu;
                                          return metric;
                                      });

    fds_gauge = GaugeInstance<int64_t>("process", "open_fds", {}, "Number of open file descriptors", "", false,
                                       []() -> prometheus::ClientMetric {
                                           auto* s = get_stats();
                                           prometheus::ClientMetric metric;
                                           metric.gauge.value = static_cast<double>(s->fds);
                                           return metric;
                                       });
#endif
}

// -- collect metric stuff -----------------------------------------------------

RecordValPtr Manager::GetMetricOptsRecord(const prometheus::MetricFamily& metric_family) {
    // Avoid recreating this repeatedly
    if ( auto it = opts_records.find(metric_family.name); it != opts_records.end() )
        return it->second;

    // Get the opt record
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
    static auto labels_idx = metric_opts_type->FieldOffset("labels");
    static auto is_total_idx = metric_opts_type->FieldOffset("is_total");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    auto record_val = make_intrusive<zeek::RecordVal>(metric_opts_type);
    record_val->Assign(name_idx, make_intrusive<zeek::StringVal>(metric_family.name));
    record_val->Assign(help_text_idx, make_intrusive<zeek::StringVal>(metric_family.help));

    // TODO: prom-cpp doesn't store the prefix information separately from the
    // name so there's no way to look this up. We could store this information
    // separately for zeek-internal metrics like we do for labels, but that
    // doesn't help for external metrics.
    // TODO: we could potentially just pull the first word off the metric name
    // up to the first underscore and return it as the prefix. The Prometheus
    // docs state that the prefix "should exist" not "must exist, so it's
    // possible we could be wrong in doing that though.
    // record_val->Assign(prefix_idx, make_intrusive<zeek::StringVal>(prefix));

    // TODO: same deal for units, but those are harder because they may be embedded in the middle
    // of the string and can have underscores in them.
    // record_val->Assign(unit_idx, make_intrusive<zeek::StringVal>(unit));

    // Assume that a metric ending with _total is always a summed metric so we can set that.
    record_val->Assign(is_total_idx, val_mgr->Bool(util::ends_with(metric_family.name, "_total")));

    auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);

    // Check if this is a Zeek-internal metric. We keep a little more information about a metric
    // for these than we do for ones that were inserted into prom-cpp directly.
    if ( auto it = families.find(metric_family.name); it != families.end() ) {
        record_val->Assign(metric_type_idx,
                           zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(it->second->MetricType()));

        for ( const auto& lbl : it->second->LabelNames() )
            label_names_vec->Append(make_intrusive<StringVal>(lbl));
    }
    else {
        // prom-cpp stores everything internally as doubles
        if ( metric_family.type == prometheus::MetricType::Counter )
            record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                    BifEnum::Telemetry::MetricType::DOUBLE_COUNTER));
        if ( metric_family.type == prometheus::MetricType::Gauge )
            record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                    BifEnum::Telemetry::MetricType::DOUBLE_GAUGE));
        if ( metric_family.type == prometheus::MetricType::Histogram )
            record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(
                                                    BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM));

        // prom-cpp doesn't store label names anywhere other than in each instrument. just assume
        // they're always going to be the same across all of the instruments and use the names from
        // the first one.
        // TODO: is this check here ever false?
        if ( ! metric_family.metric.empty() )
            for ( const auto& lbl : metric_family.metric[0].label )
                label_names_vec->Append(make_intrusive<StringVal>(lbl.name));
    }

    record_val->Assign(labels_idx, label_names_vec);

    opts_records.insert({metric_family.name, record_val});

    return record_val;
}

static bool compare_string_vectors(const VectorValPtr& a, const VectorValPtr& b) {
    if ( a->Size() < b->Size() )
        return true;
    if ( a->Size() > b->Size() )
        return false;

    auto a_v = a->RawVec();
    auto b_v = b->RawVec();

    auto b_it = b_v.begin();
    for ( auto a_it = a_v.begin(); a_it != a_v.end(); ++a_it, ++b_it ) {
        if ( ! a_it->has_value() )
            return false;
        if ( ! b_it->has_value() )
            return true;

        if ( (*a_it)->AsString()->ToStdStringView() < (*b_it)->AsString()->ToStdStringView() )
            return true;
    }

    return false;
}

static bool sorter(const std::optional<ZVal>& a, const std::optional<ZVal>& b, const RecordTypePtr& type) {
    if ( ! a )
        return false;

    if ( ! b )
        return true;

    auto a_r = a->ToVal(type)->AsRecordVal();
    auto b_r = b->ToVal(type)->AsRecordVal();

    auto a_labels = a_r->GetField<VectorVal>("labels");
    auto b_labels = b_r->GetField<VectorVal>("labels");
    return compare_string_vectors(a_labels, b_labels);
}

static bool sort_metrics(const std::optional<ZVal>& a, const std::optional<ZVal>& b) {
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    return sorter(a, b, metric_record_type);
}

static bool sort_histograms(const std::optional<ZVal>& a, const std::optional<ZVal>& b) {
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    return sorter(a, b, metric_record_type);
}

ValPtr Manager::CollectMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("Telemetry::MetricVector");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_record_type = zeek::id::find_type<zeek::RecordType>("Telemetry::Metric");
    static auto opts_idx = metric_record_type->FieldOffset("opts");
    static auto labels_idx = metric_record_type->FieldOffset("labels");
    static auto value_idx = metric_record_type->FieldOffset("value");
    static auto count_value_idx = metric_record_type->FieldOffset("count_value");

    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Due to the name containing the full information about a metric including a potential unit add an
    // asterisk to the end of the full pattern so matches work correctly.
    std::string full_pattern = util::fmt("%s_%s", prefix_pattern.data(), name_pattern.data());
    if ( full_pattern[full_pattern.size() - 1] != '*' )
        full_pattern.append("*");

    auto collected = prometheus_registry->Collect();
    for ( const auto& fam : collected ) {
        if ( fam.type == prometheus::MetricType::Histogram )
            continue;

        if ( fnmatch(full_pattern.c_str(), fam.name.c_str(), 0) == FNM_NOMATCH )
            continue;

        // TODO: it'd be nice if the prometheus::MetricFamily included the constant labels stored in
        // the metric family object in the registry. In the meantime, use the label names from the
        // first metric in the family.
        RecordValPtr opts_record = GetMetricOptsRecord(fam);

        for ( const auto& inst : fam.metric ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& label : inst.label ) {
                // We don't include the endpoint key/value unless it's a prometheus request
                if ( label.name != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label.value));
            }

            auto r = make_intrusive<zeek::RecordVal>(metric_record_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            if ( fam.type == prometheus::MetricType::Counter )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(inst.counter.value));
            else if ( fam.type == prometheus::MetricType::Gauge )
                r->Assign(value_idx, zeek::make_intrusive<DoubleVal>(inst.gauge.value));

            // Use the information from GetMetaricOptsRecord to check whether we need to add the integer
            // fields, or if this is a double.
            if ( opts_record->GetField<EnumVal>(metric_type_idx)->Get() ==
                 BifEnum::Telemetry::MetricType::INT_COUNTER ) {
                r->Assign(count_value_idx, val_mgr->Count(static_cast<int64_t>(inst.counter.value)));
            }
            else if ( opts_record->GetField<EnumVal>(metric_type_idx)->Get() ==
                      BifEnum::Telemetry::MetricType::INT_GAUGE ) {
                r->Assign(count_value_idx, val_mgr->Count(static_cast<int64_t>(inst.gauge.value)));
            }

            ret_val->Append(r);
        }
    }

    // If running under btest, there are issues with the non-deterministic
    // ordering of the metrics coming out of prometheus-cpp, which uses
    // std::hash on the label values to sort them. Check for that case and sort
    // the results to some fixed order so that the tests have consistent
    // results.
    if ( ret_val->Size() > 0 && getenv("TEST_NAME") != nullptr ) {
        auto& vec = ret_val->RawVec();
        std::sort(vec.begin(), vec.end(), sort_metrics);
    }

    return ret_val;
}

ValPtr Manager::CollectHistogramMetrics(std::string_view prefix_pattern, std::string_view name_pattern) {
    static auto metrics_vector_type = zeek::id::find_type<VectorType>("Telemetry::HistogramMetricVector");
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
    static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");
    static auto histogram_metric_type = zeek::id::find_type<zeek::RecordType>("Telemetry::HistogramMetric");
    static auto labels_idx = histogram_metric_type->FieldOffset("labels");
    static auto values_idx = histogram_metric_type->FieldOffset("values");
    static auto count_values_idx = histogram_metric_type->FieldOffset("count_values");

    static auto observations_idx = histogram_metric_type->FieldOffset("observations");
    static auto count_observations_idx = histogram_metric_type->FieldOffset("count_observations");

    static auto sum_idx = histogram_metric_type->FieldOffset("sum");
    static auto count_sum_idx = histogram_metric_type->FieldOffset("count_sum");

    static auto opts_idx = histogram_metric_type->FieldOffset("opts");
    static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto bounds_idx = opts_rt->FieldOffset("bounds");
    static auto count_bounds_idx = opts_rt->FieldOffset("count_bounds");

    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");

    VectorValPtr ret_val = make_intrusive<VectorVal>(metrics_vector_type);

    // Due to the name containing the full information about a metric including a potential unit add an
    // asterisk to the end of the full pattern so matches work correctly.
    std::string full_pattern = util::fmt("%s_%s", prefix_pattern.data(), name_pattern.data());
    if ( full_pattern[full_pattern.size() - 1] != '*' )
        full_pattern.append("*");

    auto collected = prometheus_registry->Collect();
    for ( const auto& fam : collected ) {
        if ( fam.type != prometheus::MetricType::Histogram )
            continue;

        if ( fnmatch(full_pattern.c_str(), fam.name.c_str(), 0) == FNM_NOMATCH )
            continue;

        // TODO: it'd be nice if the prometheus::MetricFamily included the constant labels stored in
        // the metric family object in the registry. In the meantime, use the label names from the
        // first metric in the family.
        RecordValPtr opts_record = GetMetricOptsRecord(fam);

        for ( const auto& inst : fam.metric ) {
            auto label_values_vec = make_intrusive<VectorVal>(string_vec_type);
            for ( const auto& label : inst.label ) {
                // We don't include the endpoint key/value unless it's a prometheus request
                if ( label.name != "endpoint" )
                    label_values_vec->Append(make_intrusive<StringVal>(label.value));
            }

            auto r = make_intrusive<zeek::RecordVal>(histogram_metric_type);
            r->Assign(labels_idx, label_values_vec);
            r->Assign(opts_idx, opts_record);

            auto double_values_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            auto count_values_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            std::vector<double> boundaries;
            uint64_t last = 0.0;
            for ( const auto& b : inst.histogram.bucket ) {
                double_values_vec->Append(
                    zeek::make_intrusive<DoubleVal>(static_cast<double>(b.cumulative_count - last)));
                count_values_vec->Append(val_mgr->Count(b.cumulative_count - last));
                last = b.cumulative_count;
                boundaries.push_back(b.upper_bound);
            }

            // TODO: these could be stored somehow to avoid recreating them repeatedly
            auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
            auto count_bounds_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
            for ( auto b : boundaries ) {
                bounds_vec->Append(zeek::make_intrusive<DoubleVal>(b));

                // The boundaries from prom-cpp include the infinite boundary in double.
                // This can't be converted safely to int64_t, so check for that case and
                // set the int64_t version.
                if ( b != std::numeric_limits<double>::infinity() )
                    count_bounds_vec->Append(val_mgr->Count(static_cast<int64_t>(b)));
                else
                    count_bounds_vec->Append(val_mgr->Count(std::numeric_limits<int64_t>::infinity()));
            }

            r->Assign(values_idx, double_values_vec);
            r->Assign(observations_idx,
                      zeek::make_intrusive<DoubleVal>(static_cast<double>(inst.histogram.sample_count)));
            r->Assign(sum_idx, zeek::make_intrusive<DoubleVal>(inst.histogram.sample_sum));

            RecordValPtr local_opts_record = r->GetField<RecordVal>(opts_idx);
            local_opts_record->Assign(bounds_idx, bounds_vec);

            // Use the information from GetMetaricOptsRecord to check whether we need to add the integer
            // fields, or if this is a double.
            if ( opts_record->GetField<EnumVal>(metric_type_idx)->Get() ==
                 BifEnum::Telemetry::MetricType::INT_HISTOGRAM ) {
                r->Assign(count_values_idx, count_values_vec);
                r->Assign(count_observations_idx, val_mgr->Count(inst.histogram.sample_count));
                r->Assign(count_sum_idx, val_mgr->Count(static_cast<int64_t>(inst.histogram.sample_sum)));
                local_opts_record->Assign(count_bounds_idx, count_bounds_vec);
            }

            ret_val->Append(r);
        }
    }

    // If running under btest, there are issues with the non-deterministic
    // ordering of the metrics coming out of prometheus-cpp, which uses
    // std::hash on the label values to sort them. Check for that case and sort
    // the results to some fixed order so that the tests have consistent
    // results.
    if ( ret_val->Size() > 0 && getenv("TEST_NAME") != nullptr ) {
        auto& vec = ret_val->RawVec();
        std::sort(vec.begin(), vec.end(), sort_histograms);
    }

    return ret_val;
}

std::string Manager::GetClusterJson() const {
    rapidjson::StringBuffer buffer;
    json::detail::NullDoubleWriter writer(buffer);

    writer.StartArray();
    writer.StartObject();

    writer.Key("targets");
    writer.StartArray();
    auto cluster_nodes = id::find_val("Cluster::nodes")->AsTableVal()->ToMap();
    for ( const auto& [idx, value] : cluster_nodes ) {
        auto node = value->AsRecordVal();
        auto ip = node->GetField<AddrVal>("ip");
        auto port = node->GetField<PortVal>("metrics_port");
        if ( port->Port() != 0 )
            writer.String(util::fmt("%s:%d", ip->Get().AsString().c_str(), port->Port()));
    }
    writer.EndArray();

    writer.Key("labels");
    writer.StartObject();
    writer.EndObject();

    writer.EndObject();
    writer.EndArray();

    return buffer.GetString();
}

} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

namespace {

template<class T>
auto toVector(zeek::Span<T> xs) {
    std::vector<std::remove_const_t<T>> result;
    for ( auto&& x : xs )
        result.emplace_back(x);
    return result;
}

} // namespace

/*
SCENARIO("telemetry managers provide access to counter families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntCounter family") {
            auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test", "1", true);
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "requests"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"method"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "1"sv);
                CHECK_EQ(family->IsSum(), true);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"method", "get"}});
                auto second = family->GetOrAdd({{"method", "get"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"method", "get"}});
                auto second = family->GetOrAdd({{"method", "put"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblCounter family") {
            auto family = mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds", true);
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "runtime"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"query"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "seconds"sv);
                CHECK_EQ(family->IsSum(), true);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"query", "foo"}});
                auto second = family->GetOrAdd({{"query", "foo"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"query", "foo"}});
                auto second = family->GetOrAdd({{"query", "bar"}});
                CHECK_NE(first, second);
            }
        }
    }
}

SCENARIO("telemetry managers provide access to gauge families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntGauge family") {
            auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test", "1");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "open_connections"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "1"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "quic"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblGauge family") {
            auto family = mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test", "meters");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "water_level"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"river"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "meters"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"river", "Sacramento"}});
                auto second = family->GetOrAdd({{"river", "Sacramento"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"query", "Sacramento"}});
                auto second = family->GetOrAdd({{"query", "San Joaquin"}});
                CHECK_NE(first, second);
            }
        }
    }
}

SCENARIO("telemetry managers provide access to histogram families") {
    GIVEN("a telemetry manager") {
        Manager mgr;
        WHEN("retrieving an IntHistogram family") {
            int64_t buckets[] = {10, 20};
            auto family = mgr.HistogramFamily("zeek", "payload-size", {"protocol"}, buckets, "test", "bytes");
            THEN("the family object stores the parameters") {
                CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "payload_size"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "bytes"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "udp"}});
                CHECK_NE(first, second);
            }
        }
        WHEN("retrieving a DblHistogram family") {
            double buckets[] = {10.0, 20.0};
            auto family = mgr.HistogramFamily<double>("zeek", "parse-time", {"protocol"}, buckets, "test",
"seconds"); THEN("the family object stores the parameters") { CHECK_EQ(family->Prefix(), "zeek"sv);
                CHECK_EQ(family->Name(), "parse_time"sv);
                CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
                CHECK_EQ(family->Helptext(), "test"sv);
                CHECK_EQ(family->Unit(), "seconds"sv);
                CHECK_EQ(family->IsSum(), false);
            }
            AND_THEN("GetOrAdd returns the same metric for the same labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "tcp"}});
                CHECK_EQ(first, second);
            }
            AND_THEN("GetOrAdd returns different metric for the disjoint labels") {
                auto first = family->GetOrAdd({{"protocol", "tcp"}});
                auto second = family->GetOrAdd({{"protocol", "udp"}});
                CHECK_NE(first, second);
            }
            AND_THEN("Timers add observations to histograms") {
                auto hg = family->GetOrAdd({{"protocol", "tst"}});
                CHECK_EQ(hg->Sum(), 0.0);
                {
                    Timer observer{hg};
                    std::this_thread::sleep_for(1ms);
                }
                CHECK_NE(hg->Sum(), 0.0);
            }
        }
    }
}
*/
