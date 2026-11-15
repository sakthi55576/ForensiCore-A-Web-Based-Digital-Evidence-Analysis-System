from datetime import datetime, timezone


def utcnow():
    """Naive UTC 'now' (whole seconds) - matches the DB DateTime columns."""

    return (
        datetime.now(timezone.utc)
        .replace(tzinfo=None, microsecond=0)
    )


from datetime import timedelta

from app.config import Config


def parse_exif_datetime(value):
    """'2026:07:31 11:15:54' -> naive datetime (device local time)."""

    if not value:
        return None

    text = str(value).strip().replace("\x00", "")

    for pattern in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], pattern)
        except ValueError:
            continue

    return None


def parse_offset_minutes(value):
    """'+05:30' -> 330 ;  '-04:00' -> -240 ; invalid -> None"""

    if not value:
        return None

    text = str(value).strip().replace("\x00", "")

    try:
        sign = -1 if text.startswith("-") else 1
        hours, minutes = text.lstrip("+-").split(":")
        return sign * (int(hours) * 60 + int(minutes))
    except (ValueError, AttributeError):
        return None


def local_to_utc(naive_local, offset_minutes=None):
    """
    Convert a timezone-less device time to UTC.

    Returns (utc_datetime, note). When the file does not state its
    own offset, the configured ASSUMED_LOCAL_UTC_OFFSET_MIN is used
    and the note says so.
    """

    if offset_minutes is not None:
        note = "Device local time, UTC{:+03d}:{:02d} from EXIF".format(
            int(offset_minutes / 60), abs(offset_minutes) % 60
        )
    else:
        offset_minutes = Config.ASSUMED_LOCAL_UTC_OFFSET_MIN
        note = "Device local time, ASSUMED UTC{:+03d}:{:02d}".format(
            int(offset_minutes / 60), abs(offset_minutes) % 60
        )

    return naive_local - timedelta(minutes=offset_minutes), note
