// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Span.h"
#include "zeek/Val.h"
#include "zeek/telemetry/MetricFamily.h"

#include "prometheus/family.h"

namespace zeek::telemetry
	{
// Convert an int64_t or double to a DoubleValPtr. int64_t is casted.
template <typename T> zeek::IntrusivePtr<zeek::DoubleVal> as_double_val(T val)
	{
	if constexpr ( std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t> )
		{
		return zeek::make_intrusive<zeek::DoubleVal>(static_cast<double>(val));
		}
	else
		{
		static_assert(std::is_same_v<T, double>);
		return zeek::make_intrusive<zeek::DoubleVal>(val);
		}
	};

prometheus::Labels convert_labels(const Span<LabelView> labels)
	{
	prometheus::Labels p_labels;
	for ( const auto& p : labels )
		p_labels.emplace(std::string{p.first}, std::string{p.second});
	return p_labels;
	}

prometheus::Labels convert_labels(Span<const LabelView> labels)
	{
	prometheus::Labels p_labels;
	for ( const auto& p : labels )
		p_labels.emplace(std::string{p.first}, std::string{p.second});
	return p_labels;
	}
	}
