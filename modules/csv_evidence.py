"""CSV logical records and verified physical spans, independent of DataFrame indexes.

Record numbers are 1-based data records (header and empty physical lines excluded).
Physical lines are 1-based and include header, blanks and quoted field newlines.
The locator iterator streams one CSV record at a time; it never reads the whole file.
"""
import csv
import hashlib
import re
from pathlib import Path

import pandas as pd

CSV_METADATA = 'aegis_csv_source_v1'
# csv.reader stores one logical record; support fields larger than its 128 KiB default.
csv.field_size_limit(max(csv.field_size_limit(), 2**31 - 1))


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def record_identity(sha256, number):
    return f'csv:{sha256}:record:{number}'


def iter_csv_locations(path_or_stream):
    """Yield (data record number, start line, end line), with strict UTF-8 CSV.

    Supports BOM, LF, CRLF and CR via newline=''. Empty/whitespace-only physical
    lines outside quoted records are skipped. Quoted empty records are retained.
    Caller-owned text streams must also use universal newline handling.
    """
    owned = not hasattr(path_or_stream, 'read')
    stream = open(path_or_stream, encoding='utf-8-sig', errors='strict', newline='') if owned else path_or_stream
    try:
        class Lines:
            blank = True
            def __iter__(self):
                return self
            def __next__(self):
                text = next(stream)
                self.blank = self.blank and not text.strip()
                if '\x00' in text:
                    raise ValueError('NUL bytes are not supported in CSV evidence.')
                return text
        lines = Lines()
        reader = csv.reader(lines, strict=True)
        header = None
        number = 0
        while True:
            start = reader.line_num + 1
            lines.blank = True
            try:
                row = next(reader)
            except StopIteration:
                break
            if not row or lines.blank:
                continue
            if header is None:
                header = len(row)
                continue
            if len(row) > header:
                raise ValueError(f'CSV record {number + 1} has more fields than its header.')
            number += 1
            yield number, start, reader.line_num
        if header is None:
            raise ValueError('CSV evidence has no header.')
    except csv.Error as exc:
        raise ValueError(f'Malformed CSV evidence: {exc}') from exc
    finally:
        if owned:
            stream.close()


def read_evidence_csv(path):
    """Keep pandas data semantics and attach independently parsed source spans.

    Location metadata stays out of model features. Disagreeing parser row counts
    fail closed because source record identity would also be ambiguous.
    """
    before = file_sha256(path)
    spans = tuple((start, end) for _, start, end in iter_csv_locations(path))
    frame = pd.read_csv(path, encoding='utf-8-sig')
    if file_sha256(path) != before:
        raise ValueError('CSV evidence changed during ingestion.')
    aligned = len(spans) == len(frame)
    if not aligned:
        raise ValueError("CSV parsers disagree on record boundaries; source record identity is unavailable.")
    frame.attrs[CSV_METADATA] = dict(sha256=before, filename=Path(path).name,
        locations={index: (position + 1, *spans[position])
                   for position, index in enumerate(frame.index)},
        physical_locations_available=aligned)
    return frame


def ensure_record_locations(frame):
    """Assign logical identities before filtering; never infer physical lines."""
    result = frame.copy()
    if CSV_METADATA not in result.attrs:
        if not result.index.is_unique:
            raise ValueError('CSV source records require unique identities.')
        result.attrs[CSV_METADATA] = dict(locations={
            index: (position + 1, None, None) for position, index in enumerate(result.index)})
    return result


def source_locator(frame, index, *, filename=None, sha256=None, position=None):
    """Use ingestion metadata first; explicit legacy line_no remains recorded data."""
    metadata = frame.attrs.get(CSV_METADATA, {})
    known_hash = metadata.get('sha256')
    if known_hash and sha256 and known_hash != sha256:
        raise ValueError('CSV source metadata does not match the evidence SHA-256.')
    sha256 = sha256 or known_hash
    locator = {}
    if filename or metadata.get('filename'):
        locator['file'] = filename or metadata['filename']
    if sha256:
        locator['sha256'] = sha256
    locations = metadata.get('locations', {})
    if index in locations:
        number, start, end = locations[index]
        locator['record_number'] = int(number)
        if start is not None:
            locator.update(line=int(start), line_end=int(end))
        if sha256:
            locator['csv_record_id'] = record_identity(sha256, number)
        return locator
    row = frame.iloc[position] if position is not None else frame.loc[index]
    # Preserve an explicit old locator, without converting an index to a line.
    if row.get('line_no') is not None and pd.notna(row.get('line_no')):
        line = row['line_no']
        if float(line) != int(line) or int(line) < 1:
            raise ValueError('Recorded CSV line number is invalid.')
        locator['line'] = int(line)
        if row.get('line_end') is not None and pd.notna(row.get('line_end')):
            locator['line_end'] = int(row['line_end'])
        return locator
    if not frame.index.is_unique:
        # Original input position is a logical ordinal, never a physical line.
        if position is None:
            raise ValueError('CSV record identity is ambiguous.')
        number = position + 1
    else:
        number = int(frame.index.get_loc(index)) + 1
    locator['record_number'] = number
    if sha256:
        locator['csv_record_id'] = record_identity(sha256, number)
    return locator


def locator_label(reference):
    number = reference.get('record_number')
    line = reference.get('line')
    end = reference.get('line_end', line)
    logical = f'logical CSV record {number}' if number is not None else ''
    physical = (f'line {line}' if end == line else f'lines {line}-{end}') if line is not None else ''
    return ', '.join(part for part in (logical, physical) if part)


def physical_line_number(content, offset):
    """Count universal newlines before a known byte/character offset, without slicing."""
    pattern = rb'\r\n|\r|\n' if isinstance(content, bytes) else r'\r\n|\r|\n'
    count = sum(1 for _ in re.compile(pattern).finditer(content, 0, offset))
    crlf = b'\r\n' if isinstance(content, bytes) else '\r\n'
    if 0 < offset < len(content) and content[offset - 1:offset + 1] == crlf:
        count -= 1
    return count + 1


def refresh_csv_session(state, frame):
    """Invalidate derived previews from an older locator scheme; keep archives intact."""
    metadata = frame.attrs.get(CSV_METADATA)
    if metadata is None:
        return
    identity = (CSV_METADATA, metadata.get('sha256'))
    if state.get('csv_locator_context') != identity:
        for key in ('ai_report', 'investigation_search_result', 'investigation_selected_finding'):
            state.pop(key, None)
        state['csv_locator_context'] = identity
