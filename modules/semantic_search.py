"""Evidence-scoped search preparation and original-record reference handling."""
import hashlib
import json
import re

from modules.semantic_matcher import SemanticMatcher
from modules.csv_evidence import CSV_METADATA, source_locator


SEARCH_VERSION = 4
NETWORK_TEXT_FIELDS = ("proto", "service", "state", "attackcat")
TEXT_FIELDS = (
    "message", "description", "eventdescription", "eventdetails", "details",
    "logcontent", "rawlog", "logmessage", "eventmessage", "eventdata",
    "scriptblocktext", "commandline", "log", "content", "text", "event",
)


def event_text_columns(frame):
    """Prefer event-content fields; never guess from dtype or column order."""
    columns = []
    for field in TEXT_FIELDS:
        for column in frame.columns:
            normalized = re.sub(r"[^a-z0-9]", "", str(column).casefold())
            if normalized == field and any(isinstance(value, str) and value.strip()
                                           for value in frame[column]):
                columns.append(column)
    if columns:
        return columns
    # A network flow is structured evidence, not prose. Index only known
    # categorical fields; targets are searchable evidence, never ML features.
    for field in NETWORK_TEXT_FIELDS:
        for column in frame.columns:
            if re.sub(r"[^a-z0-9]", "", str(column).casefold()) == field:
                if any(isinstance(value, str) and value.strip() for value in frame[column]):
                    columns.append(column)
    return columns


def prepare_evidence_search(frame, *, sha256, case_id, query, filename,
                            max_records=10_000, model_name="all-MiniLM-L6-v2",
                            source_rows=None):
    if max_records < 1:
        raise ValueError("The search record limit must be positive.")
    search_frame = frame.head(max_records)
    columns = event_text_columns(search_frame)
    records = []
    for position in range(len(search_frame)):
        row = search_frame.iloc[position]
        parts = [f"{column}: {row[column].strip()}" for column in columns
                 if isinstance(row[column], str) and row[column].strip()]
        if not parts:
            continue
        reference = {
            "record_position": position,
            "record_number": position + 1,
            "source_index": search_frame.index[position],
            "file": filename,
            "sha256": sha256,
            "case_id": case_id,
        }
        if not filename.lower().endswith(".csv") and CSV_METADATA not in frame.attrs:
            locator = {}
        elif CSV_METADATA in frame.attrs:
            locator = source_locator(frame, search_frame.index[position], filename=filename, sha256=sha256)
        elif source_rows is not None and position < len(source_rows):
            if CSV_METADATA in source_rows.attrs:
                locator = source_locator(source_rows, search_frame.index[position], filename=filename, sha256=sha256)
            elif (frame.index.is_unique and source_rows.index.is_unique
                  and search_frame.index[position] in source_rows.index):
                locator = source_locator(source_rows, search_frame.index[position],
                    filename=filename, sha256=sha256)
            else:
                # Positional coincidence cannot establish a legacy source line.
                locator = source_locator(frame, search_frame.index[position],
                    filename=filename, sha256=sha256, position=position)
        else:
            locator = source_locator(frame, search_frame.index[position],
                filename=filename, sha256=sha256, position=position)
        reference.update(locator)
        if locator.get("line") is not None:
            reference["source_line"] = locator["line"]
            reference["source_line_end"] = locator.get("line_end", locator["line"])
        records.append({**reference, "event": " | ".join(parts)})
    parameters = {
        "version": SEARCH_VERSION, "sha256": sha256, "case_id": case_id,
        "query": query.strip(), "filename": filename, "model_name": model_name,
        "max_records": max_records, "columns": list(columns),
        "total_records": len(frame), "records": records,
    }
    key = hashlib.sha256(json.dumps(parameters, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return {**parameters, "key": key, "searched_records": len(search_frame)}


def search_evidence(prepared):
    """Map ranked matches to original rows by position, including duplicate text."""
    records = prepared["records"]
    result = {key: value for key, value in prepared.items() if key != "records"}
    result.update(matches=[], mode="no_input", error=None)
    if not records or not prepared["query"]:
        return result
    matcher = SemanticMatcher(model_name=prepared["model_name"])
    matches = matcher.correlate_events([record["event"] for record in records], prepared["query"])
    if matcher.last_mode == "lexical_heuristic":
        # Character resemblance alone is not evidence of a lexical match.
        tokens = set(re.findall(r"[a-z0-9]+", prepared["query"].casefold()))
        matches = [match for match in matches if tokens.intersection(
            re.findall(r"[a-z0-9]+", records[match["record_position"]]["event"].casefold()))]
    result.update(
        matches=[{**match, **records[match["record_position"]]} for match in matches],
        mode=matcher.last_mode, error=matcher.last_error,
        model_provenance=matcher.last_provenance, score_meaning=matcher.last_provenance.get("score_meaning"),
    )
    return result
