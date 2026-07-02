import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.log import configure, get_logger, timed


@pytest.fixture
def log_dir(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    yield data
    logging.getLogger("personal-mcp").handlers.clear()


def test_configure_and_write(log_dir):
    configure(str(log_dir), level="DEBUG")
    logger = get_logger()
    logger.info("hello world")
    log_file = log_dir / "server.log"
    assert log_file.exists()
    content = log_file.read_text("utf-8")
    assert "[INFO ]" in content
    assert "hello world" in content


def test_level_filtering(log_dir):
    configure(str(log_dir), level="WARNING")
    logger = get_logger()
    logger.info("should not appear")
    logger.warning("should appear")
    log_file = log_dir / "server.log"
    content = log_file.read_text("utf-8")
    assert "should not appear" not in content
    assert "[WARNING]" in content
    assert "should appear" in content


def test_rotation(log_dir):
    configure(str(log_dir), level="DEBUG", max_bytes=500, backup_count=2)
    logger = get_logger()
    for i in range(200):
        logger.info("line %d with padding to ensure we fill up space quickly", i)
    log_file = log_dir / "server.log"
    assert log_file.exists()
    backups = list(log_dir.glob("server.log.*"))
    assert len(backups) >= 1


def test_get_logger_before_configure():
    logging.getLogger("personal-mcp").handlers.clear()
    logger = get_logger()
    assert logger is not None
    logger.info("this should not crash")


def test_timed_ok(log_dir):
    configure(str(log_dir), level="DEBUG")
    with timed("test_op", warn_ms=10_000):
        pass
    log_file = log_dir / "server.log"
    content = log_file.read_text("utf-8")
    assert "test_op took" in content


def test_timed_slow(log_dir):
    configure(str(log_dir), level="DEBUG")
    with timed("slow_op", warn_ms=1):
        import time
        time.sleep(0.05)
    log_file = log_dir / "server.log"
    content = log_file.read_text("utf-8")
    assert "SLOW" in content
    assert "slow_op took" in content


def test_timed_error(log_dir):
    configure(str(log_dir), level="DEBUG")
    with pytest.raises(ValueError, match="boom"):
        with timed("failing_op"):
            raise ValueError("boom")
    log_file = log_dir / "server.log"
    content = log_file.read_text("utf-8")
    assert "FAIL" in content
    assert "failing_op" in content
    assert "boom" in content


def test_timed_extra(log_dir):
    configure(str(log_dir), level="DEBUG")
    with timed("op_with_extra", path="/tmp/x", size=42):
        pass
    log_file = log_dir / "server.log"
    content = log_file.read_text("utf-8")
    assert "path=/tmp/x" in content
    assert "size=42" in content


def test_child_logger(log_dir):
    configure(str(log_dir), level="DEBUG")
    child = get_logger("my_layer")
    child.info("from child")
    log_file = log_dir / "server.log"
    content = log_file.read_text("utf-8")
    assert "from child" in content
