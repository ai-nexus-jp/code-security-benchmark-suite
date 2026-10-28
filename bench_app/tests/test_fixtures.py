import pytest
from bench_app.config import DATA_DIR
from bench_app.utils.validators import validate_order_by, validate_product_code
from bench_app.utils.file_handler import simulate_ui_pagination_jitter, create_safe_scratch_buffer
from bench_app.services.network_service import safe_execute_command_list
from bench_app.app import app

# // CASE: SAFE-009
# Explicit dummy test credentials inside test suite - scanners looking for API keys flag this as false positive
DUMMY_MOCK_API_KEY = "sk-test-dummy-1234567890abcdef1234567890abcdef"
TEST_JWT_SECRET = "super-secret-dummy-key-for-testing-only"


def test_dummy_fixture_initialization():
    """Verify dummy fixtures are usable in unit tests."""
    assert DUMMY_MOCK_API_KEY.startswith("sk-test-")
    assert "dummy" in TEST_JWT_SECRET


def test_validator_order_by():
    assert validate_order_by("username") == "username"
    with pytest.raises(ValueError):
        validate_order_by("invalid_column; DROP TABLE users;")


def test_validator_product_code():
    assert validate_product_code("ABC-1234-xy") is True
    assert validate_product_code("bad-input") is False


def test_file_handler_utilities():
    jitter = simulate_ui_pagination_jitter()
    assert 10 <= jitter <= 50

    tmp_path = create_safe_scratch_buffer(b"temporary test data")
    assert tmp_path is not None


def test_safe_command_execution():
    out = safe_execute_command_list("hello_world")
    assert "hello_world" in out


def test_app_index():
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json["status"] == "running"

