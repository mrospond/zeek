#include "Utils.h"

#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/util.h"

using namespace zeek;

namespace zeek::telemetry {

std::string BuildFullPrometheusName(std::string_view prefix, std::string_view name, std::string_view unit,
                                    bool is_sum) {
    if ( prefix.empty() || name.empty() )
        reporter->FatalError("Telemetry metric families must have a non-zero-length prefix and name");

    std::string fn = util::fmt("%s_%s", prefix.data(), name.data());
    std::for_each(fn.begin(), fn.end(), [](char& c) {
        if ( ! std::isalnum(c) )
            c = '_';
    });

    // We were previously using "1" to mean "no unit value" for whatever reason, so we have to handle that now
    // to mean the same thing.
    if ( ! unit.empty() && unit != "1" )
        fn.append("_").append(unit);

    if ( is_sum )
        fn.append("_total");

    return fn;
}

prometheus::Labels BuildPrometheusLabels(Span<const LabelView> labels) {
    prometheus::Labels p_labels;

    bool found_endpoint = false;
    for ( const auto& lbl : labels ) {
        p_labels.emplace(util::strreplace(std::string{lbl.first}, "-", "_"), lbl.second);
        if ( lbl.first == "endpoint" )
            found_endpoint = true;
    }

    if ( ! found_endpoint ) {
        auto endpoint = id::find_val("Telemetry::metrics_endpoint_name")->AsStringVal();
        if ( endpoint && endpoint->Len() > 0 )
            p_labels.emplace("endpoint", endpoint->ToStdString());
    }

    return p_labels;
}

template<typename T>
RecordValPtr GetMetricOptsRecord(prometheus::Family<T>* family, zeek_int_t metric_type) {
    static auto string_vec_type = zeek::id::find_type<zeek::VectorType>("string_vec");
    static auto metric_opts_type = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");

    static auto prefix_idx = metric_opts_type->FieldOffset("prefix");
    static auto name_idx = metric_opts_type->FieldOffset("name");
    static auto help_text_idx = metric_opts_type->FieldOffset("help_text");
    static auto unit_idx = metric_opts_type->FieldOffset("unit");
    static auto labels_idx = metric_opts_type->FieldOffset("labels");
    static auto metric_type_idx = metric_opts_type->FieldOffset("metric_type");
    static auto is_total_idx = metric_opts_type->FieldOffset("is_total");

    auto record_val = make_intrusive<zeek::RecordVal>(metric_opts_type);

    // Make the assumption that the first word in a metric name (before the first underscore) will always
    // be a prefix name, such as we enforce in BuildFullPrometheusName(). This could break for external
    // metrics, but we can yell at people for that if they do it wrong.
    auto parts = util::split(family->Name(), "_");
    record_val->Assign(prefix_idx, make_intrusive<zeek::StringVal>(parts[0]));

    // The name field will now always contain the full metric name including prefix, name, and units.
    record_val->Assign(name_idx, make_intrusive<zeek::StringVal>(family->Name()));

    // We unfortunately have no way to determine what part of the full name is the unit.
    //    record_val->Assign(unit_idx, make_intrusive<zeek::StringVal>(unit));

    record_val->Assign(help_text_idx, make_intrusive<zeek::StringVal>(family->Helptext()));

    auto label_names_vec = make_intrusive<zeek::VectorVal>(string_vec_type);
    for ( const auto& lbl : family->ConstantLabels() )
        label_names_vec->Append(make_intrusive<StringVal>(lbl.first));

    record_val->Assign(labels_idx, label_names_vec);
    record_val->Assign(metric_type_idx, zeek::BifType::Enum::Telemetry::MetricType->GetEnumVal(metric_type));
    record_val->Assign(is_total_idx, val_mgr->Bool(parts.back() == "total"));

    return record_val;
}

} // namespace zeek::telemetry
