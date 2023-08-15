// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/telemetry/Manager.h"

#include <algorithm>
#include <thread>
#include <variant>

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/telemetry/Collect.h"
#include "zeek/telemetry/Timer.h"
#include "zeek/telemetry/telemetry.bif.h"
#include "zeek/zeek-version.h"

namespace zeek::telemetry
	{

Manager::Manager()
	: metrics_name("zeek"), metrics_version(VERSION),
	  metrics_schema("https://opentelemetry.io/schemas/1.2.0")
	{
	registry = std::make_shared<prometheus::Registry>();
	}

Manager::~Manager() { }

void Manager::InitPostScript()
	{
	if ( auto env = getenv("BROKER_METRICS_PORT") )
		{
		auto url = util::fmt("localhost:%s", env);
		exposer = std::make_unique<prometheus::Exposer>(url);
		exposer->RegisterCollectable(registry);
		}
	}

std::shared_ptr<MetricFamily> Manager::LookupFamily(std::string_view prefix,
                                                    std::string_view name) const
	{
	auto check = [&](const auto& fam)
	{
		return fam->Prefix() == prefix && fam->Name() == name;
	};

	if ( auto it = std::find_if(families.begin(), families.end(), check); it != families.end() )
		return *it;

	return nullptr;
	}

// -- collect metric stuff -----------------------------------------------------

std::vector<CollectedValueMetric> Manager::CollectMetrics(std::string_view prefix,
                                                          std::string_view name)
	{
	std::vector<CollectedValueMetric> result;

	for ( const auto& family : families )
		{
		if ( family->Matches(prefix, name) )
			{
			auto metrics = family->CollectMetrics();
			std::move(metrics.begin(), metrics.end(), std::back_inserter(result));
			}
		}

	return result;
	}

std::vector<CollectedHistogramMetric> Manager::CollectHistogramMetrics(std::string_view prefix,
                                                                       std::string_view name)
	{
	std::vector<CollectedHistogramMetric> result;

	for ( const auto& family : families )
		{
		if ( family->Matches(prefix, name) )
			{
			auto metrics = family->CollectHistogramMetrics();
			std::move(metrics.begin(), metrics.end(), std::back_inserter(result));
			}
		}

	return result;
	}

	} // namespace zeek::telemetry

// -- unit tests ---------------------------------------------------------------

using namespace std::literals;
using namespace zeek::telemetry;

namespace
	{

template <class T> auto toVector(zeek::Span<T> xs)
	{
	std::vector<std::remove_const_t<T>> result;
	for ( auto&& x : xs )
		result.emplace_back(x);
	return result;
	}

	} // namespace

SCENARIO("telemetry managers provide access to counter families")
	{
	GIVEN("a telemetry manager")
		{
		Manager mgr;
		WHEN("retrieving an IntCounter family")
			{
			auto family = mgr.CounterFamily("zeek", "requests", {"method"}, "test", "1", true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "requests"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"method"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "1"sv);
				CHECK_EQ(family->IsSum(), true);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"method", "get"}});
				auto second = family->GetOrAdd({{"method", "get"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"method", "get"}});
				auto second = family->GetOrAdd({{"method", "put"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblCounter family")
			{
			auto family = mgr.CounterFamily<double>("zeek", "runtime", {"query"}, "test", "seconds",
			                                        true);
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "runtime"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"query"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "seconds"sv);
				CHECK_EQ(family->IsSum(), true);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"query", "foo"}});
				auto second = family->GetOrAdd({{"query", "foo"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"query", "foo"}});
				auto second = family->GetOrAdd({{"query", "bar"}});
				CHECK_NE(first, second);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to gauge families")
	{
	GIVEN("a telemetry manager")
		{
		Manager mgr;
		WHEN("retrieving an IntGauge family")
			{
			auto family = mgr.GaugeFamily("zeek", "open-connections", {"protocol"}, "test");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "open-connections"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "1"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "quic"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblGauge family")
			{
			auto family = mgr.GaugeFamily<double>("zeek", "water-level", {"river"}, "test",
			                                      "meters");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "water-level"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"river"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "meters"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"river", "Sacramento"}});
				auto second = family->GetOrAdd({{"river", "Sacramento"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"query", "Sacramento"}});
				auto second = family->GetOrAdd({{"query", "San Joaquin"}});
				CHECK_NE(first, second);
				}
			}
		}
	}

SCENARIO("telemetry managers provide access to histogram families")
	{
	GIVEN("a telemetry manager")
		{
		Manager mgr;
		WHEN("retrieving an IntHistogram family")
			{
			int64_t buckets[] = {10, 20};
			auto family = mgr.HistogramFamily("zeek", "payload-size", {"protocol"}, buckets, "test",
			                                  "bytes");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "payload-size"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "bytes"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "udp"}});
				CHECK_NE(first, second);
				}
			}
		WHEN("retrieving a DblHistogram family")
			{
			double buckets[] = {10.0, 20.0};
			auto family = mgr.HistogramFamily<double>("zeek", "parse-time", {"protocol"}, buckets,
			                                          "test", "seconds");
			THEN("the family object stores the parameters")
				{
				CHECK_EQ(family->Prefix(), "zeek"sv);
				CHECK_EQ(family->Name(), "parse-time"sv);
				CHECK_EQ(toVector(family->LabelNames()), std::vector{"protocol"s});
				CHECK_EQ(family->Helptext(), "test"sv);
				CHECK_EQ(family->Unit(), "seconds"sv);
				CHECK_EQ(family->IsSum(), false);
				}
			AND_THEN("GetOrAdd returns the same metric for the same labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "tcp"}});
				CHECK_EQ(first, second);
				}
			AND_THEN("GetOrAdd returns different metric for the disjoint labels")
				{
				auto first = family->GetOrAdd({{"protocol", "tcp"}});
				auto second = family->GetOrAdd({{"protocol", "udp"}});
				CHECK_NE(first, second);
				}
			AND_THEN("Timers add observations to histograms")
				{
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
