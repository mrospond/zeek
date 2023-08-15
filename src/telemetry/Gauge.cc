#include "zeek/telemetry/Gauge.h"

using namespace zeek::telemetry;

IntGaugeFamily::IntGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               prometheus::Registry& registry, std::string_view unit, bool is_sum)
	: BaseGaugeFamily(prefix, name, labels, helptext, registry, unit, is_sum)
	{
	}

DblGaugeFamily::DblGaugeFamily(std::string_view prefix, std::string_view name,
                               Span<const std::string_view> labels, std::string_view helptext,
                               prometheus::Registry& registry, std::string_view unit, bool is_sum)
	: BaseGaugeFamily(prefix, name, labels, helptext, registry, unit, is_sum)
	{
	}
