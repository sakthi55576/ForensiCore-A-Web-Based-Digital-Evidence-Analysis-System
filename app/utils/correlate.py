"""
Cross-evidence correlation.

Looks for moments where evidence from DIFFERENT files/modules lines up
in time, for example:

    a photo was captured at 11:15   ->  the browser downloaded a file
                                        at 11:22
    an email was sent at 09:00      ->  the browser visited a site
                                        at 09:04

The result is a set of leads for the investigator, not proof of
anything - timestamps from different devices can be off.
"""

from datetime import timedelta

ANCHOR_TYPES = ("photo_captured", "email_sent")


def find_correlations(events, window_minutes=30, limit=12):

    window = timedelta(minutes=window_minutes)

    anchors = [e for e in events if e.event_type in ANCHOR_TYPES]

    results = []

    for anchor in anchors:

        nearby = [
            e for e in events
            if e.evidence_id != anchor.evidence_id
            and e.module != anchor.module
            and abs(e.event_time - anchor.event_time) <= window
        ]

        if not nearby:
            continue

        nearby.sort(
            key=lambda e: abs(e.event_time - anchor.event_time)
        )

        results.append({
            "anchor": anchor,
            "nearby": nearby[:5],
            "count": len(nearby),
            "window": window_minutes
        })

    results.sort(key=lambda r: -r["count"])

    return results[:limit]
