from asyncpg.exceptions import UniqueViolationError
import ipaddress
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient
from app import app
from datetime import datetime
from fastapi import HTTPException


sample_ip_range = {"cidr": "173.99.253.0/24"}
sample_event = {
    "timestamp": datetime.now(),
    "username": "alice",
    "source_ip": "173.99.253.17",
    "event_type": "login",
    "file_size_mb": 5.0,
    "application": "email",
    "success": True,
}
sample_events = [sample_event]

sample_invalid_ip_range = {"cidr": "invalid_cidr"}

sample_invalid_event = {
    "timestamp": datetime.now(),
    "username": "alice",
    "source_ip": "invalid_ip_format",  # invalid IP to trigger ValueError
    "event_type": "login",
    "file_size_mb": 5.0,
    "application": "email",
    "success": True,
}

# Mock functions
@pytest.fixture(autouse=True)
def mock_database_operations():
    with patch(
        "crud.add_ip_range", new=AsyncMock(return_value=None)
    ) as mock_add_ip_range, patch(
        "crud.get_ip_ranges", new=AsyncMock(return_value=[sample_ip_range])
    ) as mock_get_ip_ranges, patch(
        "crud.delete_ip_range", new=AsyncMock(return_value=None)
    ) as mock_delete_ip_range, patch(
        "crud.process_event", new=AsyncMock(return_value=True)
    ) as mock_process_event, patch(
        "crud.get_suspicious_events", new=AsyncMock(return_value=sample_events)
    ) as mock_get_suspicious_events:
        yield {
            "mock_add_ip_range": mock_add_ip_range,
            "mock_get_ip_ranges": mock_get_ip_ranges,
            "mock_delete_ip_range": mock_delete_ip_range,
            "mock_process_event": mock_process_event,
            "mock_get_suspicious_events": mock_get_suspicious_events,
        }


# Fixture for AsyncClient
@pytest.fixture
async def test_client():
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


# Test case for adding a valid IP range
@pytest.mark.asyncio
async def test_add_ip_range(test_client, mock_database_operations):
    response = await test_client.post("/ip-ranges", json=sample_ip_range)
    assert response.status_code == 201
    assert response.json() == {"message": "IP range added"}
    mock_database_operations["mock_add_ip_range"].assert_called_once_with(
        sample_ip_range["cidr"]
    )


# Test case for adding an invalid IP range
@pytest.mark.asyncio
async def test_add_invalid_ip_range(test_client):
    response = await test_client.post("/ip-ranges", json=sample_invalid_ip_range)
    assert response.status_code == 422
    assert "does not appear to be an IPv4 or IPv6 network" in response.json()["detail"]


@pytest.mark.asyncio
async def test_add_existing_ip_range(test_client, mock_database_operations):
    # Configure the mock to raise UniqueViolationError
    mock_database_operations["mock_add_ip_range"].side_effect = UniqueViolationError(
        "This IP range already exists."
    )

    response = await test_client.post("/ip-ranges", json=sample_ip_range)
    assert response.status_code == 422
    assert response.json() == {"detail": "This IP range already exists."}
    mock_database_operations["mock_add_ip_range"].assert_called_once_with(
        sample_ip_range["cidr"]
    )


# Test case for retrieving IP ranges
@pytest.mark.asyncio
async def test_get_ip_ranges(test_client, mock_database_operations):
    response = await test_client.get("/ip-ranges")
    assert response.status_code == 200
    ip_ranges = response.json()
    assert ip_ranges == [sample_ip_range]
    mock_database_operations["mock_get_ip_ranges"].assert_called_once()


# Test case for deleting an IP range successfully
@pytest.mark.asyncio
async def test_delete_ip_range(test_client, mock_database_operations):
    response = await test_client.delete(
        "/ip-ranges", params={"cidr": sample_ip_range["cidr"]}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "IP range deleted"}
    mock_database_operations["mock_delete_ip_range"].assert_called_once_with(
        sample_ip_range["cidr"]
    )


# Test case for deleting a non-existent IP range
@pytest.mark.asyncio
async def test_delete_nonexistent_ip_range(test_client, mock_database_operations):
    mock_database_operations["mock_delete_ip_range"].side_effect = HTTPException(
        status_code=404, detail="IP range not found"
    )
    response = await test_client.delete("/ip-ranges", params={"cidr": "192.0.2.0/24"})
    assert response.status_code == 422
    assert response.json() == {"detail": "IP range not found"}


# Test case for processing a suspicious event successfully
@pytest.mark.asyncio
async def test_process_event(test_client, mock_database_operations):
    request_data = [
        {
            "timestamp": event["timestamp"].isoformat(),
            "username": event["username"],
            "source_ip": str(event["source_ip"]),
            "event_type": event["event_type"],
            "file_size_mb": event["file_size_mb"],
            "application": event["application"],
            "success": event["success"],
        }
        for event in sample_events
    ]

    response = await test_client.post("/process-event", json=request_data)
    assert response.status_code == 200
    results = response.json()
    assert len(results) == len(sample_events)
    assert results[0]["is_suspicious"] is True

    actual_call_args = mock_database_operations["mock_process_event"].call_args[0][0]

    # Convert `source_ip` to string if it's an IPv4Address
    if isinstance(actual_call_args["source_ip"], ipaddress.IPv4Address):
        actual_call_args["source_ip"] = str(actual_call_args["source_ip"])
    expected_event = sample_event.copy()
    expected_event["source_ip"] = str(expected_event["source_ip"])
    mock_database_operations["mock_process_event"].assert_called_once_with(sample_event)


# Test case for processing a invalid suspicious event
@pytest.mark.asyncio
async def test_process_event_value_error(test_client, mock_database_operations):
    request_data = [
        {
            "timestamp": event["timestamp"].isoformat(),
            "username": event["username"],
            "source_ip": "invalid_ip_format",
            "event_type": event["event_type"],
            "file_size_mb": event["file_size_mb"],
            "application": event["application"],
            "success": event["success"],
        }
        for event in sample_events
    ]

    mock_database_operations["mock_process_event"].side_effect = ValueError(
        "Invalid IP address format"
    )

    response = await test_client.post("/process-event", json=request_data)
    assert response.status_code == 422
    response_data = response.json()
    validation_error = response_data["detail"][0]

    assert validation_error["msg"] == "value is not a valid IPv4 or IPv6 address"
    assert validation_error["loc"] == ["body", 0, "source_ip"]
    assert validation_error["type"] == "ip_any_address"


# Test case for fetching suspicious events
@pytest.mark.asyncio
async def test_get_suspicious_events(test_client, mock_database_operations):
    response = await test_client.get("/suspicious-events")
    assert response.status_code == 200
    events = response.json()
    assert len(events) == len(sample_events)
    mock_database_operations["mock_get_suspicious_events"].assert_called_once()


# Test case for invalid event data (e.g., invalid IP address)
@pytest.mark.asyncio
async def test_invalid_event_data(test_client):
    invalid_event = {
        "timestamp": datetime.now().isoformat(),
        "username": "bob",
        "source_ip": "invalid_ip",  # Invalid IP
        "event_type": "file_upload",
        "application": "file_manager",
        "success": True,
    }
    response = await test_client.post("/process-event", json=[invalid_event])
    assert response.status_code == 422
    assert (
        "value is not a valid IPv4 or IPv6 address"
        in response.json()["detail"][0]["msg"]
    )
