import unittest
from datetime import datetime
from log_analyzer.parser import LogEntry
from log_analyzer.stats import StatsAggregator


def make_entry(
    ip="10.0.0.1",
    hour=12,
    endpoint="/index.html",
    status=200,
    method="GET",
    size=100,
):
    return LogEntry(
        ip=ip,
        timestamp=datetime(2023, 10, 10, hour, 0, 0),
        method=method,
        endpoint=endpoint,
        protocol="HTTP/1.1",
        status=status,
        size=size,
    )


class TestBasicCounts(unittest.TestCase):
    def test_empty_aggregator_reports_zero(self):
        agg = StatsAggregator()
        summary = agg.summary()
        self.assertEqual(summary.total_requests, 0)
        self.assertEqual(summary.unique_ip_count, 0)
        self.assertEqual(summary.error_rate, 0.0)
        self.assertEqual(summary.top_endpoints, [])

    def test_total_requests_counts_every_entry(self):
        agg = StatsAggregator()
        for _ in range(5):
            agg.add(make_entry())
        self.assertEqual(agg.summary().total_requests, 5)

    def test_unique_ip_count_deduplicates(self):
        agg = StatsAggregator()
        agg.add(make_entry(ip="1.1.1.1"))
        agg.add(make_entry(ip="1.1.1.1"))
        agg.add(make_entry(ip="2.2.2.2"))
        self.assertEqual(agg.summary().unique_ip_count, 2)

    def test_add_all_convenience_method(self):
        agg = StatsAggregator()
        entries = [make_entry(ip="1.1.1.1"), make_entry(ip="2.2.2.2"), make_entry(ip="1.1.1.1")]
        agg.add_all(entries)
        summary = agg.summary()
        self.assertEqual(summary.total_requests, 3)
        self.assertEqual(summary.unique_ip_count, 2)


class TestTopEndpoints(unittest.TestCase):
    def test_top_endpoints_sorted_by_count_descending(self):
        agg = StatsAggregator()
        for _ in range(5):
            agg.add(make_entry(endpoint="/popular"))
        for _ in range(2):
            agg.add(make_entry(endpoint="/less-popular"))
        agg.add(make_entry(endpoint="/rare"))

        top = agg.summary(top_n=10).top_endpoints
        self.assertEqual(top[0], ("/popular", 5))
        self.assertEqual(top[1], ("/less-popular", 2))
        self.assertEqual(top[2], ("/rare", 1))

    def test_top_n_limits_result_count(self):
        agg = StatsAggregator()
        for i in range(15):
            agg.add(make_entry(endpoint=f"/page-{i}"))

        top = agg.summary(top_n=10).top_endpoints
        self.assertEqual(len(top), 10)

    def test_top_n_larger_than_available_endpoints(self):
        agg = StatsAggregator()
        agg.add(make_entry(endpoint="/only-one"))

        top = agg.summary(top_n=10).top_endpoints
        self.assertEqual(top, [("/only-one", 1)])


class TestErrorRate(unittest.TestCase):
    def test_error_rate_is_zero_with_no_errors(self):
        agg = StatsAggregator()
        for _ in range(10):
            agg.add(make_entry(status=200))
        self.assertEqual(agg.summary().error_rate, 0.0)

    def test_error_rate_counts_4xx_and_5xx(self):
        agg = StatsAggregator()
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=404))  # error
        agg.add(make_entry(status=500))  # error

        summary = agg.summary()
        self.assertEqual(summary.error_count, 2)
        self.assertEqual(summary.error_rate, 50.0)

    def test_3xx_is_not_counted_as_error(self):
        agg = StatsAggregator()
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=301))
        self.assertEqual(agg.summary().error_count, 0)

    def test_status_code_counts_breakdown(self):
        agg = StatsAggregator()
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=404))
        summary = agg.summary()
        self.assertEqual(summary.status_code_counts, {200: 2, 404: 1})


class TestHourlyDistribution(unittest.TestCase):
    def test_all_24_hours_present_even_if_empty(self):
        agg = StatsAggregator()
        agg.add(make_entry(hour=5))
        distribution = agg.summary().hourly_distribution
        self.assertEqual(len(distribution), 24)
        self.assertEqual(distribution[5], 1)
        self.assertEqual(distribution[0], 0)

    def test_requests_bucketed_by_correct_hour(self):
        agg = StatsAggregator()
        agg.add(make_entry(hour=9))
        agg.add(make_entry(hour=9))
        agg.add(make_entry(hour=17))

        distribution = agg.summary().hourly_distribution
        self.assertEqual(distribution[9], 2)
        self.assertEqual(distribution[17], 1)
        self.assertEqual(distribution[10], 0)


class TestSummaryToDict(unittest.TestCase):
    def test_to_dict_is_json_serializable_shape(self):
        import json

        agg = StatsAggregator()
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=404))

        payload = agg.summary(top_n=5).to_dict()
        serialized = json.dumps(payload)
        self.assertIn("total_requests", payload)
        self.assertIn("top_endpoints", payload)
        self.assertIsInstance(serialized, str)

    def test_to_dict_rounds_error_rate(self):
        agg = StatsAggregator()
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=200))
        agg.add(make_entry(status=404))

        payload = agg.summary().to_dict()
        self.assertEqual(payload["error_rate_percent"], 33.33)


if __name__ == "__main__":
    unittest.main()
