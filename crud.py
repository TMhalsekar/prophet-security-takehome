from models import suspicious_ip_ranges, events, flagged_users, flagged_ips
from database import database
from sqlalchemy import select, exists, func, cast
from sqlalchemy.dialects.postgresql import INET, CIDR

import datetime


# CRUD functions for Suspicious IP Ranges
async def add_ip_range(cidr: str):
    """Add an IP range in CIDR notation to the suspicious IP ranges table.

    Parameters:
    cidr (str): The CIDR notation of the IP range to add.

    Returns:
    The result of the database execution.
    """
    query = suspicious_ip_ranges.insert().values(cidr=cidr)
    return await database.execute(query)


async def get_ip_ranges():
    """Retrieve all IP ranges in CIDR notation from the suspicious IP ranges table.

    Returns:
    A list of all CIDR notations stored in the database.
    """
    query = select(suspicious_ip_ranges.c.cidr)
    return await database.fetch_all(query)


async def delete_ip_range(cidr: str):
    """Delete an IP range in CIDR notation from the suspicious IP ranges table.

    Parameters:
    cidr (str): The CIDR notation of the IP range to delete.

    Raises:
    ValueError: If the specified IP range is not found in the table.
    """
    query = suspicious_ip_ranges.delete().where(
        suspicious_ip_ranges.c.cidr == cast(cidr, CIDR)
    )
    rows_affected = await database.execute(query)

    # Check if the row was deleted, otherwise raise an error
    if rows_affected == 0:
        raise ValueError("IP range not found")


async def is_ip_suspicious(ip: INET) -> bool:
    """Check if a given IP address falls within any of the suspicious IP ranges.

    Parameters:
    ip (INET): The IP address to check.

    Returns:
    bool: True if the IP address is in a suspicious range, False otherwise.
    """
    # ip_addr = ipaddress.ip_address(ip)
    # Use the << operator to check if the IP falls within any range in the `suspicious_ip_ranges` table
    ip_as_inet = func.cast(ip, INET)

    # Use the << operator via op()
    condition = ip_as_inet.op("<<")(suspicious_ip_ranges.c.cidr)

    # Build the query
    query = select(exists().where(condition))

    # Execute the query
    result = await database.fetch_val(query)
    return result


async def is_user_flagged(user: str) -> bool:
    """Check if a user has previously been flagged as suspicious.

    Parameters:
    user (str): The username to check.

    Returns:
    bool: True if the user is flagged, False otherwise.
    """
    query = select(exists().where(flagged_users.c.user == user))
    result = await database.fetch_val(query)
    return result


async def is_ip_flagged(ip: INET) -> bool:
    """Check if an IP address has previously been flagged as suspicious.

    Parameters:
    ip (INET): The IP address to check.

    Returns:
    bool: True if the IP is flagged, False otherwise.
    """
    query = select(exists().where(flagged_ips.c.ip == ip))
    result = await database.fetch_val(query)
    return result


async def process_event(event: dict) -> bool:
    """Process an event to determine if it is suspicious and store it in the database.

    Parameters:
    event (dict): A dictionary containing event details, including fields like
                  'username', 'source_ip', 'timestamp', 'event_type', 'file_size_mb',
                  'application', and 'success'.

    Returns:
    bool: True if the event is flagged as suspicious, False otherwise.
    """
    user = event["username"]
    ip = event["source_ip"]

    is_suspicious = False
    user_is_flagged = await is_user_flagged(user)
    ip_is_flagged = await is_ip_flagged(ip)
    ip_is_suspicious = await is_ip_suspicious(ip)

    if ip_is_suspicious or user_is_flagged or ip_is_flagged:
        is_suspicious = True

        if not user_is_flagged:
            await flag_user(user)

        if not ip_is_flagged:
            await flag_ip(ip)

    query = events.insert().values(
        timestamp=event["timestamp"],  # Convert ISO to datetime
        username=user,
        source_ip=ip,
        event_type=event["event_type"],
        file_size_mb=event.get("file_size_mb"),  # Optional field
        application=event["application"],
        success=event["success"],
        is_suspicious=is_suspicious,
    )
    await database.execute(query)
    return is_suspicious


async def get_suspicious_events(
    start_date: datetime = None,
    end_date: datetime = None,
    limit: int = 200,
    offset: int = 0,
):
    """Retrieve suspicious events with optional date filtering and pagination.

    Parameters:
    - start_date (datetime, optional): Filter for events on or after this date.
    - end_date (datetime, optional): Filter for events on or before this date.
    - limit (int, optional): Max number of records to retrieve. Default is 200.
    - offset (int, optional): Number of records to skip. Default is 0.

    Returns:
    List[Row]: A list of suspicious events, ordered by timestamp in descending order.
    """
    query = events.select().where(events.c.is_suspicious == True)

    # Apply date filters if provided
    if start_date:
        query = query.where(events.c.timestamp >= start_date)
    if end_date:
        query = query.where(events.c.timestamp <= end_date)

    # Order by the most recent events first
    query = query.order_by(events.c.timestamp.desc()).limit(limit).offset(offset)
    return await database.fetch_all(query)


async def flag_user(user: str):
    """Flag a user as suspicious by adding their username to the flagged users table.

    Parameters:
    user (str): The username of the user to flag.
    """
    query = flagged_users.insert().values(user=user)
    await database.execute(query)


async def flag_ip(ip: INET):
    """Flag an IP address as suspicious by adding it to the flagged IPs table.

    Parameters:
    ip (INET): The IP address to flag.
    """
    query = flagged_ips.insert().values(ip=ip)
    await database.execute(query)
