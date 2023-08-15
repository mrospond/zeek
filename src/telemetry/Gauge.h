// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Util.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "prometheus/family.h"
#include "prometheus/gauge.h"
#include "prometheus/registry.h"

namespace zeek::telemetry
	{

template <typename BaseType> class BaseGauge
	{
public:
	using Handle = prometheus::Gauge;
	using FamilyType = prometheus::Family<Handle>;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { Inc(1); }

	/**
	 * Increments the value by @p amount.
	 */
	void Inc(BaseType amount) noexcept { handle.Increment(amount); }

	/**
	 * Increments the value by 1.
	 * @return The new value.
	 */
	BaseType operator++() noexcept
		{
		Inc(1);
		return static_cast<BaseType>(handle.Value());
		}

	/**
	 * Decrements the value by 1.
	 */
	void Dec() noexcept { Dec(1); }

	/**
	 * Decrements the value by @p amount.
	 */
	void Dec(int64_t amount) noexcept { handle.Decrement(amount); }

	/**
	 * Decrements the value by 1.
	 * @return The new value.
	 */
	int64_t operator--() noexcept
		{
		Dec(1);
		return static_cast<BaseType>(handle.Value());
		}

	BaseType Value() const noexcept { return static_cast<BaseType>(handle.Value()); }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	bool IsSameAs(const BaseGauge<BaseType>& other) const noexcept
		{
		return handle == other.handle;
		}

	bool operator==(const BaseGauge<BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
	bool operator!=(const BaseGauge<BaseType>& rhs) const noexcept { return ! IsSameAs(rhs); }

	std::vector<std::string> Labels() const { return label_values; }
	bool CompareLabels(const prometheus::Labels& other) const { return labels == other; }

protected:
	explicit BaseGauge(FamilyType& family, const prometheus::Labels& labels) noexcept
		: handle(family.Add(labels)), labels(labels)
		{
		for ( const auto& [k, v] : labels )
			label_values.push_back(v);
		}

	// TODO: is a reference valid here?
	Handle& handle;
	prometheus::Labels labels;
	std::vector<std::string> label_values;
	};

/**
 * A handle to a metric that represents an integer value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class IntGauge : public BaseGauge<int64_t>
	{
public:
	static inline const char* OpaqueName = "IntGaugeMetricVal";

	explicit IntGauge(FamilyType& handle, const prometheus::Labels& labels) noexcept
		: BaseGauge(handle, labels)
		{
		}

	IntGauge(const IntGauge&) = delete;
	IntGauge& operator=(const IntGauge&) = delete;
	};

/**
 * A handle to a metric that represents an double value. Gauges are more
 * permissive than counters and also allow decrementing the value.
 */
class DblGauge : public BaseGauge<double>
	{
public:
	static inline const char* OpaqueName = "DblGaugeMetricVal";

	explicit DblGauge(FamilyType& handle, const prometheus::Labels& labels) noexcept
		: BaseGauge(handle, labels)
		{
		}

	DblGauge(const DblGauge&) = delete;
	DblGauge& operator=(const DblGauge&) = delete;
	};

template <class GaugeType, typename BaseType>
class BaseGaugeFamily : public MetricFamily,
						public std::enable_shared_from_this<BaseGaugeFamily<GaugeType, BaseType>>
	{
public:
	BaseGaugeFamily(std::string_view prefix, std::string_view name,
	                Span<const std::string_view> labels, std::string_view helptext,
	                prometheus::Registry& registry, std::string_view unit = "1",
	                bool is_sum = false)
		: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
		{
		std::string full_name = util::fmt("%s-%s", prefix.data(), name.data());
		family =
			prometheus::BuildGauge().Name(full_name).Help(std::string{helptext}).Register(registry);
		}

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<GaugeType> GetOrAdd(Span<const LabelView> labels)
		{
		prometheus::Labels p_labels;

		auto check = [&](const std::shared_ptr<GaugeType>& gauge)
		{
			return gauge->CompareLabels(p_labels);
		};

		if ( auto it = std::find_if(gauges.begin(), gauges.end(), check); it != gauges.end() )
			return *it;

		auto gauge = std::make_shared<GaugeType>(family, p_labels);
		gauges.push_back(gauge);
		return gauge;
		}

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<GaugeType> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	/**
	 * @return All gauge metrics and their values matching prefix and name.
	 * @param prefix The prefix pattern to use for filtering. Supports globbing.
	 * @param name The name pattern to use for filtering. Supports globbing.
	 */
	std::vector<CollectedValueMetric> CollectMetrics() const override
		{
		std::vector<CollectedValueMetric> result;
		result.reserve(gauges.size());

		for ( const auto& cntr : gauges )
			result.emplace_back(MetricType(), this->shared_from_this(), cntr->Labels(),
			                    cntr->Value());

		return result;
		}

protected:
	prometheus::Family<prometheus::Gauge>& family;
	std::vector<std::shared_ptr<GaugeType>> gauges;
	};

/**
 * Manages a collection of IntGauge metrics.
 */
class IntGaugeFamily : public BaseGaugeFamily<IntGauge, int64_t>
	{
public:
	static inline const char* OpaqueName = "IntGaugeMetricFamilyVal";

	IntGaugeFamily(std::string_view prefix, std::string_view name,
	               Span<const std::string_view> labels, std::string_view helptext,
	               prometheus::Registry& registry, std::string_view unit = "1",
	               bool is_sum = false);

	zeek_int_t MetricType() const noexcept override
		{
		return BifEnum::Telemetry::MetricType::INT_GAUGE;
		}
	};

/**
 * Manages a collection of DblGauge metrics.
 */
class DblGaugeFamily : public BaseGaugeFamily<DblGauge, double>
	{
public:
	static inline const char* OpaqueName = "DblGaugeMetricFamilyVal";

	DblGaugeFamily(std::string_view prefix, std::string_view name,
	               Span<const std::string_view> labels, std::string_view helptext,
	               prometheus::Registry& registry, std::string_view unit = "1",
	               bool is_sum = false);

	zeek_int_t MetricType() const noexcept override
		{
		return BifEnum::Telemetry::MetricType::DOUBLE_GAUGE;
		}
	};

namespace detail
	{

template <class T> struct GaugeOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Gauge<T> only supports int64_t and double");

	using type = IntGauge;
	};

template <> struct GaugeOracle<double>
	{
	using type = DblGauge;
	};

	} // namespace detail

template <class T> using Gauge = typename detail::GaugeOracle<T>::type;

	} // namespace zeek::telemetry
