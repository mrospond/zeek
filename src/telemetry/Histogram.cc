#include "zeek/telemetry/Histogram.h"

using namespace zeek::telemetry;

IntHistogramFamily::IntHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, prometheus::Registry& registry,
                                       std::string_view unit, bool is_sum)
	: BaseHistogramFamily(prefix, name, labels, helptext, registry, unit, is_sum)
	{
	}

DblHistogramFamily::DblHistogramFamily(std::string_view prefix, std::string_view name,
                                       Span<const std::string_view> labels,
                                       std::string_view helptext, prometheus::Registry& registry,
                                       std::string_view unit, bool is_sum)
	: BaseHistogramFamily(prefix, name, labels, helptext, registry, unit, is_sum)
	{
	}
