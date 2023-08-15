// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <initializer_list>
#include <type_traits>

#include "zeek/Span.h"
#include "zeek/telemetry/MetricFamily.h"
#include "zeek/telemetry/Util.h"
#include "zeek/telemetry/telemetry.bif.h"

#include "prometheus/counter.h"
#include "prometheus/family.h"
#include "prometheus/registry.h"

namespace zeek::telemetry
	{

class Manager;
extern telemetry::Manager* telemetry_mgr;

template <typename BaseType> class BaseCounter
	{
public:
	using Handle = prometheus::Counter;
	using FamilyType = prometheus::Family<Handle>;

	/**
	 * Increments the value by 1.
	 */
	void Inc() noexcept { Inc(1); }

	/**
	 * Increments the value by @p amount.
	 * @pre `amount >= 0`
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

	BaseType Value() const noexcept { return static_cast<BaseType>(handle.Value()); }

	/**
	 * @return Whether @c this and @p other refer to the same counter.
	 */
	bool IsSameAs(const BaseCounter<BaseType>& other) const noexcept
		{
		return handle == other.handle;
		}

	bool operator==(const BaseCounter<BaseType>& rhs) const noexcept { return IsSameAs(rhs); }
	bool operator!=(const BaseCounter<BaseType>& rhs) const noexcept { return ! IsSameAs(rhs); }

	std::vector<std::string> Labels() const { return label_values; }
	bool CompareLabels(const prometheus::Labels& other) const { return labels == other; }

protected:
	explicit BaseCounter(FamilyType& family, const prometheus::Labels& labels) noexcept
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
 * A handle to a metric that represents an integer value that can only go up.
 */
class IntCounter : public BaseCounter<uint64_t>
	{
public:
	static inline const char* OpaqueName = "IntCounterMetricVal";

	explicit IntCounter(FamilyType& family, const prometheus::Labels& labels) noexcept
		: BaseCounter(family, labels)
		{
		}
	};

/**
 * A handle to a metric that represents an floating point value that can only go up.
 */
class DblCounter : public BaseCounter<double>
	{
public:
	static inline const char* OpaqueName = "DblCounterMetricVal";
	explicit DblCounter(FamilyType& family, const prometheus::Labels& labels) noexcept
		: BaseCounter(family, labels)
		{
		}
	};

template <class CounterType, typename BaseType>
class BaseCounterFamily
	: public MetricFamily,
	  public std::enable_shared_from_this<BaseCounterFamily<CounterType, BaseType>>
	{
public:
	BaseCounterFamily(std::string_view prefix, std::string_view name,
	                  Span<const std::string_view> labels, std::string_view helptext,
	                  prometheus::Registry& registry, std::string_view unit = "1",
	                  bool is_sum = false)
		: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
		{
		std::string full_name = util::fmt("%s-%s", prefix.data(), name.data());
		family = prometheus::BuildCounter()
		             .Name(full_name)
		             .Help(std::string{helptext})
		             .Register(registry);
		}

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<CounterType> GetOrAdd(Span<const LabelView> labels)
		{
		prometheus::Labels p_labels;

		auto check = [&](const std::shared_ptr<CounterType>& counter)
		{
			return counter->CompareLabels(p_labels);
		};

		if ( auto it = std::find_if(counters.begin(), counters.end(), check); it != counters.end() )
			return *it;

		auto counter = std::make_shared<CounterType>(family, p_labels);
		counters.push_back(counter);
		return counter;
		}

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<CounterType> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	/**
	 * @return All counter metrics and their values matching prefix and name.
	 * @param prefix The prefix pattern to use for filtering. Supports globbing.
	 * @param name The name pattern to use for filtering. Supports globbing.
	 */
	std::vector<CollectedValueMetric> CollectMetrics() const override
		{
		std::vector<CollectedValueMetric> result;
		result.reserve(counters.size());

		for ( const auto& cntr : counters )
			result.emplace_back(MetricType(), this->shared_from_this(), cntr->Labels(),
			                    cntr->Value());

		return result;
		}

protected:
	prometheus::Family<prometheus::Counter>& family;
	std::vector<std::shared_ptr<CounterType>> counters;
	};

/**
 * Manages a collection of IntCounter metrics.
 */
class IntCounterFamily : public BaseCounterFamily<IntCounter, uint64_t>
	{
public:
	static inline const char* OpaqueName = "IntCounterMetricFamilyVal";

	explicit IntCounterFamily(std::string_view prefix, std::string_view name,
	                          Span<const std::string_view> labels, std::string_view helptext,
	                          prometheus::Registry& registry, std::string_view unit = "1",
	                          bool is_sum = false);

	IntCounterFamily() = delete;

	zeek_int_t MetricType() const noexcept override
		{
		return BifEnum::Telemetry::MetricType::INT_COUNTER;
		}
	};

/**
 * Manages a collection of DblCounter metrics.
 */
class DblCounterFamily : public BaseCounterFamily<DblCounter, double>
	{
public:
	static inline const char* OpaqueName = "DblCounterMetricFamilyVal";

	explicit DblCounterFamily(std::string_view prefix, std::string_view name,
	                          Span<const std::string_view> labels, std::string_view helptext,
	                          prometheus::Registry& registry, std::string_view unit = "1",
	                          bool is_sum = false);

	DblCounterFamily() = delete;

	zeek_int_t MetricType() const noexcept override
		{
		return BifEnum::Telemetry::MetricType::DOUBLE_COUNTER;
		}
	};

namespace detail
	{

template <class T> struct CounterOracle
	{
	static_assert(std::is_same<T, int64_t>::value, "Counter<T> only supports uint64_t and double");

	using type = IntCounter;
	};

template <> struct CounterOracle<double>
	{
	using type = DblCounter;
	};

	} // namespace detail

template <class T> using Counter = typename detail::CounterOracle<T>::type;

	} // namespace zeek::telemetry
