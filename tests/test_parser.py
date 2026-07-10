import unittest
from datetime import datetime, timezone, timedelta
from log_analyzer.parser import parse_line, _parse_line_strict, LogParseError, LogEntry

VALID_LINE = (
    '127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] '
    '"GET /index.html HTTP/1.1" 200 2326 "http://referrer.com" "Mozilla/5.0"'
)

class TestValidLines(unittest.TestCase):
    def test_parses_well_formed_line(self):
        entry = parse_line(VALID_LINE)
        self.assertIsInstance(entry, LogEntry)

    def test_extracts_ip(self):
        entry = parse_line(VALID_LINE)
        self.assertEqual(entry.ip, "127.0.0.1")

    def test_extracts_method_endpoint_protocol(self):
        entry = parse_line(VALID_LINE)
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.endpoint, "/index.html")
        self.assertEqual(entry.protocol, "HTTP/1.1")

    def test_extracts_status_and_size(self):
        entry = parse_line(VALID_LINE)
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 2326)

    def test_extracts_referrer_and_user_agent(self):
        entry = parse_line(VALID_LINE)
        self.assertEqual(entry.referrer, "http://referrer.com")
        self.assertEqual(entry.user_agent, "Mozilla/5.0")

    def test_extracts_correct_timestamp(self):
        entry = parse_line(VALID_LINE)
        expected = datetime(2023, 10, 10, 13, 55, 36, tzinfo=timezone(timedelta(hours=-7)))
        self.assertEqual(entry.timestamp, expected)

    def test_line_without_referrer_or_user_agent_still_parses(self):
        line = '192.168.1.5 - - [10/Oct/2023:13:56:01 -0700] "POST /login HTTP/1.1" 401 512'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertIsNone(entry.referrer)
        self.assertIsNone(entry.user_agent)
        self.assertEqual(entry.status, 401)
        self.assertEqual(entry.size, 512)

    def test_dash_size_is_normalized_to_zero(self):
        line = '10.0.0.2 - - [10/Oct/2023:14:02:15 -0700] "GET /api/data HTTP/1.1" 200 -'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.size, 0)

    def test_ipv6_address_is_accepted(self):
        line = '::1 - - [10/Oct/2023:14:02:15 -0700] "GET / HTTP/1.1" 200 100'
        entry = parse_line(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "::1")

    def test_trailing_newline_does_not_break_parsing(self):
        entry = parse_line(VALID_LINE + "\n")
        self.assertIsNotNone(entry)

    def test_error_status_flagged_correctly(self):
        error_line = '10.0.0.1 - - [10/Oct/2023:14:00:00 -0700] "GET /missing HTTP/1.1" 404 0'
        ok_line = '10.0.0.1 - - [10/Oct/2023:14:00:00 -0700] "GET /ok HTTP/1.1" 200 0'
        self.assertTrue(parse_line(error_line).is_error)
        self.assertFalse(parse_line(ok_line).is_error)


class TestInvalidLines(unittest.TestCase):
    def test_empty_string_returns_none(self):
        self.assertIsNone(parse_line(""))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(parse_line("   \n"))

    def test_completely_garbage_line_returns_none(self):
        self.assertIsNone(parse_line("this is not a log line at all"))

    def test_missing_ip_returns_none(self):
        line = 'malformed [10/Oct/2023:15:01:00 -0700] "GET /x HTTP/1.1" 200 10'
        self.assertIsNone(parse_line(line))

    def test_missing_status_code_returns_none(self):
        line = '10.0.0.1 - - [10/Oct/2023:14:00:00 -0700] "GET /x HTTP/1.1" 10'
        self.assertIsNone(parse_line(line))

    def test_bad_timestamp_returns_none(self):
        line = '10.0.0.1 - - [not-a-real-date] "GET /x HTTP/1.1" 200 10'
        self.assertIsNone(parse_line(line))

    def test_status_code_out_of_range_returns_none(self):
        line = '10.0.0.1 - - [10/Oct/2023:14:00:00 -0700] "GET /x HTTP/1.1" 999 10'
        self.assertIsNone(parse_line(line))

    def test_non_numeric_status_returns_none(self):
        line = '10.0.0.1 - - [10/Oct/2023:14:00:00 -0700] "GET /x HTTP/1.1" ABC 10'
        self.assertIsNone(parse_line(line))

    def test_invalid_ip_shaped_token_returns_none(self):
        # Looks vaguely IP-like but octets are out of range / wrong shape
        line = '999.999.999.999 - - [10/Oct/2023:14:00:00 -0700] "GET /x HTTP/1.1" 200 10'
        self.assertIsNone(parse_line(line))

    def test_strict_variant_raises_with_reason(self):
        line = "garbage"
        with self.assertRaises(LogParseError):
            _parse_line_strict(line)


if __name__ == "__main__":
    unittest.main()
