from fastapi import FastAPI, HTTPException, status, Query, Request

from typing import List
from pydantic import BaseModel, IPvAnyAddress
from database import connect_db, disconnect_db, engine, metadata
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from asyncpg.exceptions import UniqueViolationError
from typing import Optional

import crud
import ipaddress
import logging



# Ensure tables are created in the database
metadata.create_all(engine)

app = FastAPI(on_startup=[connect_db], on_shutdown=[disconnect_db])

logger = logging.getLogger("FastAPI TestLogger")


# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*"
    ],  # Allow all origins; restrict to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)


# Pydantic models for request and response validation
class Event(BaseModel):
    """Model for event data"""

    timestamp: datetime
    username: str
    source_ip: IPvAnyAddress
    event_type: str
    file_size_mb: Optional[float] = None
    application: str
    success: bool


class EventResponse(BaseModel):
    """Model for event response, indicating if the event is suspicious"""

    user: str
    ip: IPvAnyAddress
    is_suspicious: bool


class IPRange(BaseModel):
    """Model for IP range data in CIDR notation"""

    cidr: str


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors with a custom response format"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": exc.errors(), "body": exc.body}),
    )


# Routes for CRUD operations on Suspicious IP Ranges
@app.post("/ip-ranges", response_model=dict, status_code=status.HTTP_201_CREATED)
async def add_ip_range(ip_range: IPRange):
    """Add a new IP range in CIDR notation.
    Checks for correct format and uniqueness before adding to the database.
    """
    try:
        ipaddress.ip_network(ip_range.cidr)
        await crud.add_ip_range(ip_range.cidr)
        return {"message": "IP range added"}
    except ValueError as e:
        logger.error(f"Format nError occurred: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    except UniqueViolationError as e:
        logger.error(f"Unique constraint error occurred: {e}")
        raise HTTPException(status_code=422, detail="This IP range already exists.")


@app.get("/ip-ranges", response_model=List[IPRange])
async def get_ip_ranges():
    """Retrieve all IP ranges"""
    rows = await crud.get_ip_ranges()
    return [IPRange(cidr=str(ipaddress.ip_network(row["cidr"]))) for row in rows]


@app.delete("/ip-ranges", response_model=dict)
async def delete_ip_range(
    cidr: str = Query(..., description="CIDR range to delete, e.g., 173.99.253.0/24")
):
    """Delete an IP range specified by CIDR notation.
    Raises an error if the IP range does not exist.
    """
    try:
        ipaddress.ip_network(cidr)
        await crud.delete_ip_range(cidr)
        return {"message": "IP range deleted"}
    except Exception as e:
        # Handle cases where the CIDR might not exist
        logger.error(f"Not found error occurred: {e}")
        raise HTTPException(status_code=422, detail="IP range not found")


# Event Processing Endpoint
@app.post("/process-event", response_model=List[EventResponse])
async def process_event_endpoint(events: List[Event]):
    """Process a list of events, marking them as suspicious if applicable.
    Returns a list event's username,ip with their suspicious status.
    """
    results = []
    for event in events:
        is_suspicious = await crud.process_event(event.dict())
        results.append(
            EventResponse(
                user=event.username, ip=event.source_ip, is_suspicious=is_suspicious
            )
        )
    return results


# Get Suspicious Events
@app.get("/suspicious-events", response_model=List[Event])
async def get_suspicious_events(
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
):
    """Retrieve a paginated list of suspicious events with optional date filtering"""
    events = await crud.get_suspicious_events(
        start_date=start_date, end_date=end_date, limit=limit, offset=offset
    )
    return events
