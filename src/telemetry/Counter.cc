#include "zeek/telemetry/Counter.h"

using namespace zeek::telemetry;

IntCounterFamily::IntCounterFamily(std::string_view prefix, std::string_view name,
                                   Span<const std::string_view> labels, std::string_view helptext,
                                   prometheus::Registry& registry, std::string_view unit,
                                   bool is_sum)
	: BaseCounterFamily(prefix, name, labels, helptext, registry, unit, is_sum)
	{
	}

DblCounterFamily::DblCounterFamily(std::string_view prefix, std::string_view name,
                                   Span<const std::string_view> labels, std::string_view helptext,
                                   prometheus::Registry& registry, std::string_view unit,
                                   bool is_sum)
	: BaseCounterFamily(prefix, name, labels, helptext, registry, unit, is_sum)
	{
	}
