"""Fail-closed report export checks; cached validation flags are never authority.

Bindings are local audit-chain commitments, not independent authentication or
proof that generated prose is true. Legacy records remain readable as drafts.
"""
import hashlib
from io import BytesIO, StringIO
import json
import re
from pathlib import Path
import zipfile

from modules.ai_reporter import LocalLLMReporter, validate_report
from modules.integrity import EvidenceIntegrity
from modules.event_timestamps import CHRONOLOGY_VERSION
from modules.csv_evidence import iter_csv_locations, record_identity

DRAFT_WARNING = 'UNVERIFIED DRAFT — citation/evidence validation has not passed. Not a validated forensic report.'


def canonical(value):
    return json.dumps(value, sort_keys=True, default=str)


def report_digest(report):
    return hashlib.sha256(canonical({k: v for k, v in report.items()
                                    if k not in {'validation', 'export_binding'}}).encode()).hexdigest()


def _check_sources(context):
    case = context['case_id']
    audit_path = context['audit_path']
    EvidenceIntegrity.read_verified_audit(case, audit_path)
    scan = context.get('scan_report')
    if scan is not None:
        if scan.get('case_id') != case:
            raise ValueError('Scan belongs to another case.')
        EvidenceIntegrity.require_scan_report(scan, audit_path)
        if context.get('scan_collection_version') is not None:
            from modules.laptop_findings import COLLECTION_VERSION, collect_laptop_findings
            if (context['scan_collection_version'] != COLLECTION_VERSION or
                    canonical(context['findings']) != canonical(collect_laptop_findings(scan))):
                raise ValueError('Laptop findings differ from the verified scan snapshot collection.')
    sources = context['sources']
    if not sources and scan is None:
        raise ValueError('No verified evidence sources recorded.')
    for source in sources:
        if scan is None:
            EvidenceIntegrity.require_evidence(case, source['path'], audit_path=audit_path,
                expected_hash=source['sha256'], scanned_record=context.get('scanned_record'))
        elif not EvidenceIntegrity.verify_file(source['path'], source['sha256']):
            raise ValueError('Scan evidence bytes changed or are unavailable.')
    if context.get('scanned_record', {}).get('case_id', case) != case:
        raise ValueError('Saved evidence belongs to another case.')


def _check_references(context):
    sources = context['sources']
    aliases = {}
    record = context.get('scanned_record') or {}
    for source in sources:
        for alias in (source['path'], Path(source['path']).name, source.get('filename')):
            if alias:
                aliases[str(alias)] = source
    if len(sources) == 1 and record.get('original_filename'):
        aliases[record['original_filename']] = sources[0]
    errors = []
    sizes = {}
    line_counts = {}
    member_data = {}
    csv_references = {}
    for finding in context['findings']:
        refs = finding.get('evidence') or finding.get('matches') or []
        if not isinstance(refs, list) or not refs or any(not isinstance(e, dict) for e in refs):
            errors.append(f"{finding.get('id')}: missing evidence references")
            continue
        refs = list(refs)
        for match in finding.get('matches') or []:
            if isinstance(match, dict) and match not in refs:
                refs.append(match)
        seen = set()
        for reference in refs:
            if not reference:
                errors.append(f"{finding['id']}: empty evidence reference")
                continue
            identity = canonical(reference)
            if identity in seen:
                errors.append(f"{finding['id']}: duplicate evidence reference")
            seen.add(identity)
            if reference.get('observation') is not None:
                # This validates provenance of a recorded observation, not the
                # current state of a live process, task, Defender or event log.
                if not context.get('scan_collection_version') or not context.get('scan_report'):
                    errors.append(f"{finding['id']}: system observation lacks a verified scan snapshot")
                elif (reference.get('observation') != finding.get('technical_record') or
                      reference.get('source_type') != finding.get('source_type')):
                    errors.append(f"{finding['id']}: observation reference differs from its recorded source")
                continue
            location = reference.get('file') or finding.get('file') or finding.get('path')
            # Native event references remain native; no fictitious CSV lines.
            event_id = reference.get('EventId', reference.get('event_id'))
            record_id = reference.get('RecordId', reference.get('record_id'))
            if event_id is not None and record_id is not None and reference.get("record_number") is None:
                if not (context.get('scan_report') or context.get('scanned_record')):
                    if not location or str(location) not in aliases:
                        errors.append(f"{finding['id']}: event reference lacks a verified source")
                continue
            source = aliases.get(str(location))
            own_path = finding.get('path')
            if own_path and str(location) == Path(own_path).name:
                source = aliases.get(str(own_path), source)
            # Archive references are bound to the verified container and the
            # stored scanner finding; retain member/hash/offset metadata intact.
            member = finding.get('member')
            if source is None and member and (context.get('scanned_record') or context.get('scan_report')):
                source = aliases.get(str(finding.get('container_path'))) or (sources[0] if len(sources) == 1 else None)
            if source is None:
                errors.append(f"{finding['id']}: evidence reference is not in the verified context")
                continue
            if finding.get('sha256') and not member and finding['sha256'].lower() != source['sha256'].lower():
                errors.append(f"{finding['id']}: finding hash does not match evidence")
            if reference.get('sha256') and not member and reference['sha256'].lower() != source['sha256'].lower():
                errors.append(f"{finding['id']}: reference hash does not match evidence")
            path = source['path']
            member_bytes = None
            if member:
                member_key = (path, member)
                if member_key not in member_data:
                    from modules.safety_checks import MAX_ARCHIVE_MEMBER_SIZE
                    try:
                        with zipfile.ZipFile(path) as archive:
                            entries = [e for e in archive.infolist() if e.filename == member]
                            if len(entries) != 1 or entries[0].file_size > MAX_ARCHIVE_MEMBER_SIZE:
                                raise ValueError('Missing, ambiguous or oversized archive member')
                            with archive.open(entries[0]) as stream:
                                data = stream.read(MAX_ARCHIVE_MEMBER_SIZE + 1)
                            if len(data) > MAX_ARCHIVE_MEMBER_SIZE:
                                raise ValueError('Oversized archive member')
                            if finding.get('member_sha256') and hashlib.sha256(data).hexdigest() != finding['member_sha256']:
                                raise ValueError('Archive member hash mismatch')
                            member_data[member_key] = data
                    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError):
                        errors.append(f"{finding['id']}: archive member cannot be verified")
                        continue
                member_bytes = member_data[member_key]
            if path not in sizes:
                sizes[path] = Path(path).stat().st_size
            if reference.get('record_number') is not None:
                number = reference['record_number']
                if type(number) is not int or number < 1:
                    errors.append(f"{finding['id']}: invalid logical CSV record number")
                else:
                    csv_references.setdefault((path, member), []).append((finding['id'], reference,
                        finding.get('member_sha256') if member else source['sha256']))
            if reference.get('line_end') is not None and (reference.get('line') is None or
                    type(reference['line_end']) is not int or type(reference['line']) is not int or
                    reference['line_end'] < reference['line']):
                errors.append(f"{finding['id']}: invalid physical line range")
            for key in ('line', 'line_end', 'page', 'offset', 'byte_offset'):
                if key not in reference or reference[key] is None:
                    continue
                value = reference[key]
                if type(value) is not int or value < (0 if key in {'offset', 'byte_offset'} else 1):
                    errors.append(f"{finding['id']}: invalid {key}")
                elif key in {'offset', 'byte_offset'} and value >= (len(member_bytes) if member else sizes[path]):
                    errors.append(f"{finding['id']}: offset outside evidence")
                elif key in {'line', 'line_end'}:
                    if member:
                        count = len(member_bytes.splitlines())
                    elif path not in line_counts:
                        with Path(path).open('r', encoding='utf-8', errors='replace', newline='') as stream:
                            line_counts[path] = sum(1 for _ in stream)
                    if not member:
                        count = line_counts[path]
                    if value > count:
                        errors.append(f"{finding['id']}: line outside evidence")
                elif key == 'page':
                    from pypdf import PdfReader
                    from pypdf.errors import PdfReadError
                    try:
                        if value > len(PdfReader(BytesIO(member_bytes) if member else path).pages):
                            errors.append(f"{finding['id']}: page outside evidence")
                    except (PdfReadError, OSError, ValueError):
                        errors.append(f"{finding['id']}: page reference cannot be verified against evidence")
    # Re-parse each CSV once, retaining only the records actually cited. This
    # checks both logical existence and the exact start/end boundaries, rather
    # than accepting any line that happens to be within the file's length.
    for (path, member), references in csv_references.items():
        wanted = {reference['record_number'] for _, reference, _ in references}
        found = {}
        try:
            target = StringIO(member_data[(path, member)].decode('utf-8-sig'), newline='') if member else path
            for number, start, end in iter_csv_locations(target):
                if number in wanted:
                    found[number] = (start, end)
            for finding_id, reference, digest in references:
                number = reference['record_number']
                span = found.get(number)
                if span is None:
                    errors.append(f"{finding_id}: logical CSV record outside evidence")
                    continue
                if reference.get('line') is not None and (reference['line'], reference.get('line_end', reference['line'])) != span:
                    errors.append(f"{finding_id}: CSV physical span differs from source record")
                if reference.get('csv_record_id') is not None and reference['csv_record_id'] != record_identity(digest, number):
                    errors.append(f"{finding_id}: CSV record identity does not match evidence")
        except (OSError, ValueError, UnicodeError) as exc:
            errors.append(f"CSV evidence locators cannot be verified: {exc}")
    return errors


def _check_content(report, context):
    if report.get('case_id') != context['case_id']:
        raise ValueError('Report belongs to another case.')
    actual = {f['id']: canonical(f) for f in context['findings']}
    for finding in report.get('findings', []):
        if actual.get(finding.get('id')) != canonical(finding):
            raise ValueError('Report findings differ from the verified finding context.')
    text = report.get('text', '')
    if context.get('scan_collection_version') is not None:
        from modules.laptop_findings import laptop_coverage_text, laptop_source_coverage
        if canonical(report.get('findings', [])) != canonical(context['findings']):
            raise ValueError('Laptop report must include the entire normalized finding collection.')
        coverage = laptop_coverage_text(context['scan_report'])
        if (not text.startswith(coverage) or report.get('source_coverage') != laptop_source_coverage(context['scan_report'])):
            raise ValueError('Laptop source coverage differs from the verified scan snapshot.')
        text = text[len(coverage):]
    if text.startswith('## Saved Evidence Record\n'):
        prefix = ('## Saved Evidence Record\n'
                  f"- Evidence ID: {report.get('evidence_id')}\n"
                  f"- Filename: {report.get('filename')}\n"
                  f"- SHA-256: {report.get('sha256')}\n"
                  f"- Scan timestamp (UTC): {report.get('scanned_at_utc')}\n")
        if not text.startswith(prefix):
            raise ValueError('Evidence metadata differs from the report context.')
        text = text[len(prefix):].lstrip('\n')
    marker = '## Evidence References'
    if marker in text:
        body, index = text.rsplit(marker, 1)
        expected = LocalLLMReporter._evidence_index(report.get('findings', []))
        if marker + index != expected:
            raise ValueError('Evidence index differs from verified findings.')
        text = body.rstrip()
    if report.get('chronology_version') is not None:
        if type(report['chronology_version']) is not int or report['chronology_version'] != CHRONOLOGY_VERSION:
            raise ValueError('Unsupported report chronology policy.')

        section = re.search(r'^## Timeline Analysis\n(.*?)(?=^## |\Z)', text,
                            flags=re.MULTILINE | re.DOTALL)
        expected = '\n'.join(LocalLLMReporter._chronology_lines(report.get('findings', [])))
        if section is None or section.group(1).strip() != expected.strip():
            raise ValueError('Report chronology differs from resolved source event times.')
    result = validate_report(text, context['findings'], case_id=context['case_id'])
    errors = _check_references(context)
    result['reference_errors'] = errors
    result['passed'] = result['passed'] and not errors
    return result


def bind_report_context(report, findings, *, audit_path=None, scanned_record=None, scan_report=None):
    """Called only at generation, after source checks, with the actual findings.

    Invalid output can be previewed, but receives no trusted export binding.
    """
    case = report['case_id']
    sources = []
    if scan_report is None:
        for path in report.get('source_paths', []):
            sources.append(dict(path=str(Path(path).resolve()), sha256=report.get('sha256'),
                                filename=report.get('filename')))
    else:
        # Inventory-only findings are bound by the scan snapshot; file findings
        # additionally require matching current bytes on every export.
        for finding in scan_report.get('findings', []):
            path = finding.get('container_path') or finding.get('path') or finding.get('file')
            digest = finding.get('container_sha256') or finding.get('sha256')
            if path and digest:
                source = dict(path=str(Path(path).resolve()), sha256=digest, filename=Path(path).name)
                if source not in sources:
                    sources.append(source)
    context = json.loads(canonical(dict(case_id=case,
        audit_path=str(Path(audit_path or EvidenceIntegrity._audit_path(case)).resolve()),
        sources=sources, findings=findings, **({'scanned_record': scanned_record} if scanned_record else {}),
        **({'scan_report': scan_report, 'scan_collection_version': 1} if scan_report is not None else {}))))
    report['validation_context'] = context
    _check_sources(context)
    report['validation'] = _check_content(report, context)
    report.pop('export_binding', None)
    if report['validation']['passed']:
        digest = report_digest(report)
        entry = EvidenceIntegrity.log_audit_trail(case, 'REPORT_EXPORT_BOUND', digest,
                                                audit_path=context['audit_path'])
        report['export_binding'] = dict(entry_hash=entry['entry_hash'], digest=digest)
    return report


def validate_report_export(report, *, expected_case_id=None, expected_sha256=None, expected_scan_snapshot_sha256=None):
    """Revalidate current bytes and text; never trust a saved 'passed' flag."""
    try:
        if expected_case_id is not None and report.get('case_id') != expected_case_id:
            raise ValueError('Cached report belongs to another case.')
        if expected_sha256 is not None and report.get('sha256') != expected_sha256:
            raise ValueError('Cached report belongs to another evidence context.')
        if expected_scan_snapshot_sha256 is not None and report.get('scan_snapshot_sha256') != expected_scan_snapshot_sha256:
            raise ValueError('Cached report belongs to another scan snapshot.')
        context = report.get('validation_context')
        binding = report.get('export_binding')
        if not context or not binding:
            raise ValueError('Unverified or legacy report: no audited export binding.')
        if binding.get('digest') != report_digest(report):
            raise ValueError('Report text, findings or context changed after generation.')
        entries = EvidenceIntegrity.read_verified_audit(context['case_id'], context['audit_path'])
        if not any(e['entry_hash'] == binding.get('entry_hash') and e['action'] == 'REPORT_EXPORT_BOUND'
                   and e['details'] == binding['digest'] for e in entries):
            raise ValueError('Report export binding is absent from the verified case audit chain.')
        _check_sources(context)
        result = _check_content(report, context)
        if not result['passed']:
            return dict(passed=False, errors=['Citation, reference or deterministic factual checks failed.'], checks=result)
        return dict(passed=True, errors=[], checks=result)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return dict(passed=False, errors=[str(exc)])


def require_report_export(report, **context):
    result = validate_report_export(report, **context)
    if not result['passed']:
        raise ValueError('Trusted report export blocked: ' + '; '.join(result['errors']))
    return result


def render_forensic_text(report, *, draft=False, **context):
    if draft:
        return DRAFT_WARNING + '\n\n' + str(report.get('text', ''))
    require_report_export(report, **context)
    return str(report['text'])
