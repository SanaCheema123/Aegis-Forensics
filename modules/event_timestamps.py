"""Conservative, shared event timestamp interpretation. No implicit Unix units or zone.

Only complete ISO dates/times with explicit zones and Windows /Date(ms)/ envelopes
establish an instant. Original values are retained. Naive/local/ambiguous values
remain unresolved; choosing a column never supplies a missing timezone.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from numbers import Number
import re

import pandas as pd

CHRONOLOGY_VERSION = 1
ALIASES = ('timeutc', 'timestamputc', 'eventtimeutc', 'utctime', 'timecreated',
           'eventtime', 'timestamp', 'datetime', 'eventtimestamp', 'timegenerated',
           'systemtime', 'occurredat', 'loggedat', 'createdatutc', 'createdat',
           'eventdate', 'time', 'date')
WINDOWS_DATE = re.compile(r'^/Date\((-?\d+)([+-]\d{4})?\)/$')
ISO_DATE_TIME = re.compile(r'^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:[Zz]|[+-]\d{2}:?\d{2})?$')
UTC_MIN = pd.Timestamp.min.tz_localize('UTC')
UTC_MAX = pd.Timestamp.max.tz_localize('UTC')


def field_key(name):
    return re.sub(r'[^a-z0-9]', '', str(name).casefold())


def identifier_field(name):
    key = field_key(name)
    return (key in {'id', 'pid', 'ppid', 'row', 'index', 'lineno', 'linenumber',
                    'recordnumber', 'rownumber', 'csvrecordid'}
            or key.endswith('id') or key.endswith('ids'))


@dataclass(frozen=True)
class TimestampValue:
    original: object
    utc: object = None
    status: str = 'missing'

    @property
    def text(self):
        return self.utc.isoformat() if self.utc is not None else None


def parse_timestamp(value):
    """Resolve an explicit instant, never a bare number or timezone-free date."""
    original = value
    if value is None or value is pd.NaT or value is pd.NA:
        return TimestampValue(original)
    if isinstance(value, Number):
        return TimestampValue(original, status='missing' if pd.isna(value) else 'numeric_identifier')
    try:
        if isinstance(value, dict):
            if set(value) == {'SystemTime'}:
                result = parse_timestamp(value['SystemTime'])
                return TimestampValue(original, result.utc, result.status)
            return TimestampValue(original, status='unsupported_format')
        if isinstance(value, (datetime, pd.Timestamp)):
            stamp = pd.Timestamp(value)
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                return TimestampValue(original)
            if re.fullmatch(r'[+-]?\d+(?:\.\d+)?', text):
                return TimestampValue(original, status='numeric_identifier')
            if re.search(r' (?:UTC|GMT)$', text):
                text = re.sub(r' (?:UTC|GMT)$', 'Z', text)
            serialized = WINDOWS_DATE.fullmatch(text)
            if serialized:
                offset = serialized.group(2)
                if offset and (int(offset[1:3]) > 23 or int(offset[3:5]) > 59):
                    return TimestampValue(original, status='malformed')
                # The suffix is source offset metadata; milliseconds already denote UTC.
                stamp = pd.Timestamp('1970-01-01T00:00:00Z') + pd.Timedelta(milliseconds=int(serialized.group(1)))
            else:
                if not ISO_DATE_TIME.fullmatch(text):
                    # A date alone cannot establish an event instant or its timezone.
                    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', text):
                        pd.Timestamp(text)  # Validate the calendar date, without assigning an instant.
                        return TimestampValue(original, status='timezone_missing')
                    return TimestampValue(original, status='unsupported_format')
                stamp = pd.Timestamp(text.replace('z', 'Z'))
        else:
            return TimestampValue(original, status='unsupported_format')
        if pd.isna(stamp):
            return TimestampValue(original)
        if stamp.tzinfo is None:
            return TimestampValue(original, status='timezone_missing')
        stamp = stamp.tz_convert('UTC')
        if stamp < UTC_MIN or stamp > UTC_MAX:
            return TimestampValue(original, status='out_of_range')
        return TimestampValue(original, stamp, 'resolved')
    except (ValueError, TypeError, OverflowError):
        return TimestampValue(original, status='malformed')


def timestamp_candidates(columns):
    """Exact supported field aliases only, independent of column position."""
    return sorted((c for c in columns if field_key(c) in ALIASES and not identifier_field(c)),
                  key=lambda c: (ALIASES.index(field_key(c)), str(c)))


def _select(columns, values, timestamp_column=None):
    if timestamp_column is not None:
        matches = [c for c in columns if c == timestamp_column]
        if not matches:
            matches = [c for c in columns if field_key(c) == field_key(timestamp_column)]
        if len(matches) != 1 or identifier_field(matches[0]):
            return dict(column=None, status='invalid_selection', candidates=[], values=[],
                        message='The selected field is missing, ambiguous, or an identifier.')
        candidates = matches
    else:
        candidates = timestamp_candidates(columns)
    if not candidates:
        return dict(column=None, status='no_timestamp_field', candidates=[], values=[],
                    message='No recognized timestamp field. Select an event timestamp column explicitly.')
    parsed = {c: [parse_timestamp(v) for v in values(c)] for c in candidates}
    valid = [c for c in candidates if any(v.utc is not None for v in parsed[c])]
    if timestamp_column is None and len(valid) > 1:
        baseline = [v.utc for v in parsed[valid[0]]]
        if any([v.utc for v in parsed[c]] != baseline for c in valid[1:]):
            return dict(column=None, status='ambiguous', candidates=candidates, values=[],
                        message='Timestamp fields disagree. Select the field that represents event time explicitly.')
    column = valid[0] if valid else candidates[0]
    resolved = sum(v.utc is not None for v in parsed[column])
    return dict(column=column, status='resolved' if resolved else 'unresolved',
                candidates=candidates, values=parsed[column], resolved=resolved,
                unresolved=len(parsed[column]) - resolved,
                message='Only timestamps with explicit timezone information enter chronology.' if resolved
                        else 'No resolved event instants: timestamps are missing, malformed, numeric, or lack a timezone.')


def select_timestamp_column(frame, timestamp_column=None):
    if not frame.columns.is_unique:
        return dict(column=None, status='ambiguous', candidates=[], values=[],
                    message='Duplicate column names make timestamp selection ambiguous.')
    return _select(list(frame.columns), lambda c: frame[c], timestamp_column)


def resolve_event_timestamp(event, timestamp_column=None):
    selection = _select(list(event), lambda c: [event[c]], timestamp_column)
    value = selection['values'][0] if selection['values'] else TimestampValue(None, status=selection['status'])
    return selection, value


def finding_time(finding, field='first_seen'):
    return parse_timestamp(finding.get(field))


def chronological_findings(findings):
    timed = []
    for finding in findings:
        value = finding_time(finding)
        if value.utc is not None:
            timed.append((value.utc, str(finding.get('id', '')), finding))
    return [(stamp, finding) for stamp, _, finding in sorted(timed, key=lambda item: (item[0], item[1]))]


def normalized_finding_facts(findings):
    return ' '.join(value.text for f in findings for key in ('first_seen', 'last_seen', 'collected_at_utc')
                    if (value := parse_timestamp(f.get(key))).utc is not None)
