from itertools import count
from unittest.mock import patch

from src.security import RateLimitError


class TestRateLimitInSecurityValidator:
    def test_rate_limit_blocks_after_limit(self, test_config, security):
        limit = test_config.security.rate_limit_commands_per_minute
        path = str(test_config.security.paths_allow[0]) + "/test.txt"

        with patch("time.time", side_effect=count(1000.0, 1)):
            for i in range(limit):
                result = security.validate_tool_path(path, "read")
                assert result is None, f"call {i} should be allowed"

            result = security.validate_tool_path(path, "read")
            assert result is not None
            assert "Rate limit exceeded" in result
            assert "read" in result

    def test_rate_limit_per_operation_separate(self, test_config, security):
        path = str(test_config.security.paths_allow[0]) + "/test.txt"
        limit = test_config.security.rate_limit_commands_per_minute

        with patch("time.time", side_effect=count(1000.0, 1)):
            for i in range(limit):
                result = security.validate_tool_path(path, "read")
                assert result is None, f"read call {i} should be allowed"

            # Write should still work (separate counter)
            result = security.validate_tool_path(path, "write")
            assert result is None or "permission" in result

    def test_rate_limit_window_expiry(self, test_config, security):
        path = str(test_config.security.paths_allow[0]) + "/test.txt"
        limit = test_config.security.rate_limit_commands_per_minute

        times = [1000.0 + i for i in range(limit)] + [1061.0]
        with patch("time.time", side_effect=times):
            for i in range(limit):
                result = security.validate_tool_path(path, "read")
                assert result is None, f"call {i} should be allowed"

            # 61 seconds later — all entries expired
            result = security.validate_tool_path(path, "read")
            assert result is None, "should be allowed after window expiry"

    def test_rate_limit_disabled(self, test_config, security):
        test_config.security.rate_limit_commands_per_minute = 0
        path = str(test_config.security.paths_allow[0]) + "/test.txt"

        security._rate_limiters.clear()

        with patch("time.time", side_effect=count(1000.0, 1)):
            for _ in range(200):
                result = security.validate_tool_path(path, "read")
                assert result is None

    def test_rate_limit_exception(self):
        exc = RateLimitError("rate limit test")
        assert "rate limit test" in str(exc)
        assert isinstance(exc, Exception)
