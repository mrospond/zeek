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
#include "prometheus/histogram.h"
#include "prometheus/registry.h"

namespace zeek::telemetry
	{

template <typename BaseType> class BaseHistogram
	{
public:
	using Handle = prometheus::Histogram;
	using FamilyType = prometheus::Family<Handle>;

	/**
	 * Increments all buckets with an upper bound less than or equal to @p value
	 * by one and adds @p value to the total sum of all observed values.
	 */
	void Observe(BaseType value) noexcept { handle.Observe(value); }

	/// @return The sum of all observed values.
	// TODO
	BaseType Sum() const noexcept { return 0; } // return sum; }

	/**
	 * @return Whether @c this and @p other refer to the same histogram.
	 */
	bool IsSameAs(const BaseHistogram& other) const noexcept { return handle == other.handle; }

	bool operator==(const BaseHistogram& other) const noexcept { return IsSameAs(other); }
	bool operator!=(const BaseHistogram& other) const noexcept { return ! IsSameAs(other); }

	std::vector<std::string> Labels() const { return label_values; }
	bool CompareLabels(const prometheus::Labels& other) const { return labels == other; }

protected:
	explicit BaseHistogram(FamilyType& family, const prometheus::Labels& labels,
	                       const prometheus::Histogram::BucketBoundaries& boundaries) noexcept
		: handle(family.Add(labels, boundaries)), labels(labels)
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
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class IntHistogram : public BaseHistogram<uint64_t>
	{
public:
	static inline const char* OpaqueName = "IntHistogramMetricVal";

	explicit IntHistogram(FamilyType& family, const prometheus::Labels& labels,
	                      const prometheus::Histogram::BucketBoundaries& boundaries) noexcept
		: BaseHistogram(family, labels, boundaries)
		{
		}

	IntHistogram() = delete;
	IntHistogram(const IntHistogram&) noexcept = delete;
	IntHistogram& operator=(const IntHistogram&) noexcept = delete;
	};

/**
 * A handle to a metric that represents an aggregable distribution of observed
 * measurements with integer precision. Sorts individual measurements into
 * configurable buckets.
 */
class DblHistogram : public BaseHistogram<double>
	{
public:
	static inline const char* OpaqueName = "DblHistogramMetricVal";

	explicit DblHistogram(FamilyType& family, const prometheus::Labels& labels,
	                      const prometheus::Histogram::BucketBoundaries& boundaries) noexcept
		: BaseHistogram(family, labels, boundaries)
		{
		}

	DblHistogram() = delete;
	DblHistogram(const DblHistogram&) noexcept = delete;
	DblHistogram& operator=(const DblHistogram&) noexcept = delete;
	};

template <class HistogramType, typename BaseType>
class BaseHistogramFamily
	: public MetricFamily,
	  public std::enable_shared_from_this<BaseHistogramFamily<HistogramType, BaseType>>
	{
public:
	BaseHistogramFamily(std::string_view prefix, std::string_view name,
	                    Span<const std::string_view> labels, std::string_view helptext,
	                    prometheus::Registry& registry, std::string_view unit = "1",
	                    bool is_sum = false)
		: MetricFamily(prefix, name, labels, helptext, unit, is_sum)
		{
		std::string full_name = util::fmt("%s-%s", prefix.data(), name.data());
		family = prometheus::BuildHistogram()
		             .Name(full_name)
		             .Help(std::string{helptext})
		             .Register(registry);
		}

	// TODO: the opentelemetry API doesn't have direct access to the bucket information
	// in the histogram instrument. In the meantime, all of these functions return zero
	// values.

	/**
	 *@return The number of buckets, including the implicit "infinite" bucket.
	 */
	size_t NumBuckets() const noexcept { return 0; }

	/**
	 * @return The number of observations in the bucket at @p index.
	 * @pre index < NumBuckets()
	 */
	BaseType CountAt(size_t index) const noexcept { return 0; }

	/**
	 * @return The upper bound of the bucket at @p index.
	 * @pre index < NumBuckets()
	 */
	BaseType UpperBoundAt(size_t index) const noexcept { return 0; }

	/**
	 * Returns the metrics handle for given labels, creating a new instance
	 * lazily if necessary.
	 */
	std::shared_ptr<HistogramType> GetOrAdd(Span<const LabelView> labels)
		{
		prometheus::Labels p_labels;

		auto check = [&](const std::shared_ptr<HistogramType>& histogram)
		{
			return histogram->CompareLabels(p_labels);
		};

		if ( auto it = std::find_if(histograms.begin(), histograms.end(), check);
		     it != histograms.end() )
			return *it;

		prometheus::Histogram::BucketBoundaries boundaries;
		auto histogram = std::make_shared<HistogramType>(family, p_labels, boundaries);
		histograms.push_back(histogram);
		return histogram;
		}

	/**
	 * @copydoc GetOrAdd
	 */
	std::shared_ptr<HistogramType> GetOrAdd(std::initializer_list<LabelView> labels)
		{
		return GetOrAdd(Span{labels.begin(), labels.size()});
		}

	/**
	 * @return All histogram metrics and their data matching prefix and name.
	 * @param prefix The prefix pattern to use for filtering. Supports globbing.
	 * @param name The name pattern to use for filtering. Supports globbing.
	 */
	std::vector<CollectedHistogramMetric> CollectHistogramMetrics() const override
		{
		std::vector<CollectedHistogramMetric> metrics;

		for ( const auto& hst : histograms )
			{
			// TODO: the opentelemetry API doesn't have direct access to the bucket information
			// in the histogram instrument. In the meantime we just return an empty set of
			// buckets.

			if constexpr ( std::is_same_v<BaseType, uint64_t> )
				{
				CollectedHistogramMetric::IntHistogramData histogram_data;
				histogram_data.sum = hst->Sum();
				metrics.emplace_back(MetricType(), this->shared_from_this(), hst->Labels(),
				                     std::move(histogram_data));
				}
			else
				{
				CollectedHistogramMetric::DblHistogramData histogram_data;
				histogram_data.sum = hst->Sum();
				metrics.emplace_back(MetricType(), this->shared_from_this(), hst->Labels(),
				                     std::move(histogram_data));
				}
			}

		return metrics;
		}

protected:
	void AddAdditionalOpts() const override
		{
		static auto double_vec_type = zeek::id::find_type<zeek::VectorType>("double_vec");
		static auto count_vec_type = zeek::id::find_type<zeek::VectorType>("index_vec");

		// Add bounds and optionally count_bounds into the MetricOpts record.
		static auto opts_rt = zeek::id::find_type<zeek::RecordType>("Telemetry::MetricOpts");
		static auto opts_rt_idx_bounds = opts_rt->FieldOffset("bounds");
		static auto opts_rt_idx_count_bounds = opts_rt->FieldOffset("count_bounds");

		auto add_double_bounds = [](auto& r, const auto* family)
		{
			size_t buckets = family->NumBuckets();
			auto bounds_vec = make_intrusive<zeek::VectorVal>(double_vec_type);
			for ( size_t i = 0; i < buckets; i++ )
				bounds_vec->Append(as_double_val(family->UpperBoundAt(i)));

			r->Assign(opts_rt_idx_bounds, bounds_vec);
		};

		add_double_bounds(record_val, this);

		if constexpr ( std::is_same_v<BaseType, uint64_t> )
			{
			// Add count_bounds to uint64_t histograms
			size_t buckets = NumBuckets();
			auto count_bounds_vec = make_intrusive<zeek::VectorVal>(count_vec_type);
			for ( size_t i = 0; i < buckets; i++ )
				count_bounds_vec->Append(val_mgr->Count(UpperBoundAt(i)));

			record_val->Assign(opts_rt_idx_count_bounds, count_bounds_vec);
			}
		}

protected:
	prometheus::Family<prometheus::Histogram>& family;
	std::vector<std::shared_ptr<HistogramType>> histograms;
	};

/**
 * Manages a collection of IntHistogram metrics.
 */
class IntHistogramFamily : public BaseHistogramFamily<IntHistogram, uint64_t>
	{
public:
	static inline const char* OpaqueName = "IntHistogramMetricFamilyVal";

	IntHistogramFamily(std::string_view prefix, std::string_view name,
	                   Span<const std::string_view> labels, std::string_view helptext,
	                   prometheus::Registry& registry, std::string_view unit = "1",
	                   bool is_sum = false);

	zeek_int_t MetricType() const noexcept override
		{
		return BifEnum::Telemetry::MetricType::INT_HISTOGRAM;
		}
	};

/**
 * Manages a collection of DblHistogram metrics.
 */
class DblHistogramFamily : public BaseHistogramFamily<DblHistogram, double>
	{
public:
	static inline const char* OpaqueName = "DblHistogramMetricFamilyVal";

	DblHistogramFamily(std::string_view prefix, std::string_view name,
	                   Span<const std::string_view> labels, std::string_view helptext,
	                   prometheus::Registry& registry, std::string_view unit = "1",
	                   bool is_sum = false);

	zeek_int_t MetricType() const noexcept override
		{
		return BifEnum::Telemetry::MetricType::DOUBLE_HISTOGRAM;
		}
	};

namespace detail
	{

template <class T> struct HistogramOracle
	{
	static_assert(std::is_same<T, uint64_t>::value,
	              "Histogram<T> only supports uint64_t and double");

	using type = IntHistogram;
	};

template <> struct HistogramOracle<double>
	{
	using type = DblHistogram;
	};

	} // namespace detail

template <class T> using Histogram = typename detail::HistogramOracle<T>::type;

	} // namespace zeek::telemetry
