import pytest
from unittest.mock import patch, MagicMock
from apex_forge.db import update_intel_stats, log_intel_history

@pytest.fixture
def mock_db_cursor():
    with patch("apex_forge.db.get_pg_cursor") as mock_cursor:
        mock_cur = MagicMock()
        mock_cursor.return_value.__enter__.return_value = mock_cur
        yield mock_cur

def test_update_intel_stats_new_profile(mock_db_cursor):
    # New profile: SELECT returns None
    mock_db_cursor.fetchone.return_value = None

    update_intel_stats("test_profile", 10, {"US": 5, "CN": 5}, high_critical_new=3, total_risk_sum=450.0)

    # Always 2 calls: SELECT + UPSERT
    assert mock_db_cursor.execute.call_count == 2

    # First call is SELECT
    select_call = mock_db_cursor.execute.call_args_list[0]
    select_query = select_call[0][0]
    select_params = select_call[0][1]
    select_normalized = " ".join(select_query.strip().split())
    assert "SELECT total_count, high_critical_count, avg_risk_score FROM intel_stats" in select_normalized
    assert select_params == ("test_profile",)

    # Second call is UPSERT
    upsert_call = mock_db_cursor.execute.call_args_list[1]
    upsert_query = upsert_call[0][0]
    upsert_params = upsert_call[0][1]
    upsert_normalized = " ".join(upsert_query.strip().split())
    assert "INSERT INTO intel_stats" in upsert_normalized
    assert "ON CONFLICT (profile_name) DO UPDATE" in upsert_normalized
    assert "high_critical_count" in upsert_normalized
    assert "avg_risk_score" in upsert_normalized

    # Parameters for new profile
    assert upsert_params[0] == "test_profile"
    assert upsert_params[1] == 10
    assert upsert_params[3] == 3
    assert abs(upsert_params[4] - 45.0) < 0.01  # 450 / 10

def test_update_intel_stats_existing_profile(mock_db_cursor):
    # Existing profile: SELECT returns values
    mock_db_cursor.fetchone.return_value = {
        "total_count": 20,
        "high_critical_count": 5,
        "avg_risk_score": 45.0
    }

    update_intel_stats("existing_profile", 15, {"DE": 10}, high_critical_new=4, total_risk_sum=600.0)

    assert mock_db_cursor.execute.call_count == 2

    # Second call is UPSERT
    upsert_call = mock_db_cursor.execute.call_args_list[1]
    upsert_params = upsert_call[0][1]

    # Running average: (45 * 20 + 600) / 35 = 42.857 → rounded to 42.86
    expected_avg = round((45.0 * 20 + 600.0) / 35, 2)
    assert abs(upsert_params[4] - expected_avg) < 0.01

def test_log_intel_history(mock_db_cursor):
    log_intel_history("test_profile", 10, high_critical_new=2)

    call_args = mock_db_cursor.execute.call_args
    query = call_args[0][0]
    params = call_args[0][1]

    query_normalized = " ".join(query.strip().split())
    assert "INSERT INTO intel_history" in query_normalized
    assert "profile_name, count, high_critical_new, observed_at" in query_normalized
    assert "CURRENT_TIMESTAMP" in query_normalized

    assert params == ("test_profile", 10, 2)