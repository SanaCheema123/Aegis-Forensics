"""Pure adapters for the recorded laptop snapshot; never query the live system.

The same collection drives dashboard cards, citations and both report formats.
System observations are bound to their recorded snapshot, not asserted to be
immutable files. Normalization never changes the original scan snapshot.
"""
from copy import deepcopy
import hashlib
import json

from modules.windows_security import normalize_security_event, _event_timestamp_values

COLLECTION_VERSION = 1
OBSERVATION_STATUS = 'Recorded system observation; not an immutable forensic artifact'


def _canonical(value):
    return json.dumps(value, sort_keys=True, default=str)


def _rows(value):
    return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []


def _unique(rows):
    return list({_canonical(row): row for row in rows}.values())


def _time(value):
    return _event_timestamp_values(value)[0] if value is not None else None


def _reasons(raw):
    values = raw.get('review_reasons') or []
    return values if isinstance(values, str) else '; '.join(str(value) for value in values)


def _base(scan, raw, source_type, source, rule, description, severity='Medium', first_seen=None):
    return dict(source=source, source_type=source_type, severity=raw.get('severity') or severity,
                rule=rule, description=description, mitre=raw.get('mitre') or 'n/a',
                first_seen=first_seen, last_seen=first_seen, users='', source_ips='', hosts='',
                case_id=raw.get('case_id', scan.get('case_id')), technical_record=deepcopy(raw),
                collected_at_utc=(scan.get('system_collection_times') or {}).get(source_type),
                evidence_status=OBSERVATION_STATUS,
                reported_sha256=raw.get('sha256') or raw.get('SHA256'),
                context_notes=[] if (scan.get('system_collection_times') or {}).get(source_type)
                else ['Collection timestamp was not recorded.'],
                recommendation='Review the recorded observation and corroborate it with preserved evidence.')


def collect_laptop_findings(scan):
    """Return complete, deduplicated findings derived only from this snapshot."""
    candidates = []
    for raw in _rows(scan.get('findings')):
        source = 'yara' if str(raw.get('source', '')).casefold() == 'yara' else 'static heuristic'
        kind = 'yara' if source == 'yara' else 'filesystem'
        finding = deepcopy(raw)
        finding.update(source=source, source_type=kind, case_id=raw.get('case_id', scan.get('case_id')),
                       original_id=raw.get('id'), technical_record=deepcopy(raw))
        finding['rule'] = str(raw.get('rule') or 'Recorded file indicator')
        finding['description'] = str(raw.get('description') or finding['rule'])
        finding.setdefault('severity', 'Medium')
        finding.setdefault('mitre', 'n/a')
        for key in ('first_seen', 'last_seen'):
            finding.setdefault(key, None)
        for key in ('users', 'source_ips', 'hosts'):
            finding.setdefault(key, '')
        path = raw.get('path') or raw.get('file')
        finding['path'] = path
        finding['file'] = raw.get('file') or path
        evidence = deepcopy(_rows(raw.get('evidence')))
        for item in evidence:
            if not item.get('file') and path:
                item['file'] = path
        # Whole-file references are legitimate, but hashes/line locations are
        # never invented. The export gate still checks current file bytes.
        if not evidence and path:
            evidence = [dict(file=path)]
        finding['evidence'] = _unique(evidence)
        finding['matches'] = _unique(deepcopy(_rows(raw.get('matches'))))
        finding['evidence_status'] = ('File hash recorded; current bytes must verify at export'
                                      if raw.get('container_sha256') or raw.get('sha256')
                                      else 'Unverified file reference; evidence hash not recorded')
        if raw.get('recommended_action'):
            finding['recommendation'] = raw['recommended_action']
        if source == 'yara':
            finding['yara_rule'] = str(raw.get('rule') or 'Recorded rule match')
            finding['rule'] = 'YARA: ' + finding['yara_rule']
        candidates.append(finding)

    defender = scan.get('defender_status') or {}
    for raw in _rows(defender.get('detections')):
        title = str(raw.get('ThreatName') or raw.get('Name') or raw.get('DetectionName') or 'Microsoft Defender detection')
        stamp = _time(raw.get('InitialDetectionTime'))
        finding = _base(scan, raw, 'defender', 'defender', title,
                        f'Microsoft Defender reported {title}. Analyst review is required.', 'High', stamp)
        finding.update(title=title, affected=str(raw.get('Resources') or raw.get('Path') or raw.get('ProcessName') or 'Microsoft Defender'),
                       detection_id=raw.get('DetectionID'), threat_id=raw.get('ThreatID'),
                       resources=deepcopy(raw.get('Resources')), path=raw.get('Path'))
        finding['evidence'] = [dict(source_type='defender', observation=deepcopy(raw),
                                    detection_id=raw.get('DetectionID'), threat_id=raw.get('ThreatID'),
                                    resources=deepcopy(raw.get('Resources')), timestamp=stamp)]
        if not (raw.get('DetectionID') or raw.get('ThreatID')):
            finding['context_notes'].append('Defender detection and threat identifiers were not recorded.')
        candidates.append(finding)

    for raw in _rows(scan.get('running_processes')):
        if not raw.get('review_reasons'):
            continue
        description = _reasons(raw)
        finding = _base(scan, raw, 'process', 'process', 'Running process requires review', description)
        finding.update(process_id=raw.get('ProcessId'), parent_process_id=raw.get('ParentProcessId'),
                       path=raw.get('ExecutablePath'), file=raw.get('ExecutablePath'),
                       process_name=raw.get('Name'), command_line=raw.get('CommandLine'))
        finding['evidence'] = [dict(source_type='process', observation=deepcopy(raw),
                                    process_id=raw.get('ProcessId'), parent_process_id=raw.get('ParentProcessId'),
                                    file=raw.get('ExecutablePath'), process_name=raw.get('Name'),
                                    command_line=raw.get('CommandLine'))]
        if raw.get('ProcessId') is None:
            finding['context_notes'].append('Process ID was not recorded.')
        candidates.append(finding)

    startup = scan.get('startup_inventory') or {}
    for key, kind in (('flagged_startup_items', 'startup'), ('flagged_scheduled_tasks', 'scheduled task')):
        for raw in _rows(startup.get(key)):
            finding = _base(scan, raw, kind, kind, 'Startup entry requires review' if kind == 'startup'
                            else 'Scheduled task requires review',
                            _reasons(raw) or 'Recorded entry was flagged for review.')
            finding.update(path=raw.get('Path') or raw.get('Location'), file=raw.get('Execute'),
                           task_name=raw.get('Name'), command_line=raw.get('Command') or raw.get('Arguments'),
                           users=str(raw.get('User') or ''))
            finding['evidence'] = [dict(source_type=kind, observation=deepcopy(raw),
                                        task_name=raw.get('Name'), task_path=raw.get('Path'),
                                        location=raw.get('Location'), command=raw.get('Command'),
                                        execute=raw.get('Execute'), arguments=raw.get('Arguments'))]
            candidates.append(finding)

    # Reuse the existing live classification policy, including suspicious 4624
    # service logons; normal logons stay out of the finding collection.
    from modules.realtime_monitor import classify_security_event, SECURITY_EVENT_SEVERITY
    for raw in _rows((scan.get('security_events') or {}).get('events')):
        event = normalize_security_event(raw)
        classification, reasons = classify_security_event(event)
        if classification == 'Normal':
            continue
        try:
            event_id = int(event.get('EventId', 0))
        except (ValueError, TypeError):
            continue
        finding = _base(scan, raw, 'windows event', 'windows event',
                        f'Windows security event {event_id}', str(event.get('description') or 'Recorded Windows security event'),
                        SECURITY_EVENT_SEVERITY.get(event_id, 'Low'), event.get('TimeUtc'))
        finding.update(event_id=event_id, record_id=raw.get('RecordId'),
                       classification=classification, classification_reasons=reasons,
                       users=event.get('account', ''), source_ips=event.get('source_ip', ''),
                       hosts=str(raw.get('Computer') or raw.get('MachineName') or ''),
                       affected=f"{raw.get('Log', 'Windows')} · Event {event_id}")
        finding['evidence'] = [dict(source_type='windows event', observation=deepcopy(raw),
                                    log=raw.get('Log'), event_id=event_id, record_id=raw.get('RecordId'),
                                    timestamp=event.get('TimeUtc'), computer=raw.get('Computer') or raw.get('MachineName'),
                                    provider=raw.get('Provider'), fingerprint=raw.get('Fingerprint'))]
        if raw.get('RecordId') is None:
            finding['context_notes'].append('Record ID was not recorded.')
        if not event.get('TimeUtc'):
            finding['context_notes'].append('Event timestamp was not recorded or could not be parsed.')
        candidates.append(finding)

    unique = {}
    for finding in candidates:
        kind = finding['source_type']
        raw = finding['technical_record']
        if finding.get('reported_sha256'):
            for reference in finding['evidence']:
                reference['reported_sha256'] = finding['reported_sha256']
        if kind == 'windows event' and raw.get('RecordId') is not None:
            reference = finding['evidence'][0]
            identity = [kind, reference['computer'], reference['log'], reference['provider'],
                        reference['event_id'], reference['record_id'], reference['timestamp'], reference['fingerprint']]
        else:
            identity = [kind, {k: v for k, v in raw.items() if k != 'id'}]
        unique.setdefault(_canonical(identity), finding)
    counters = {'F': 0, 'Y': 0}
    findings = []
    for identity, finding in sorted(unique.items()):
        if finding['source_type'] in {'filesystem', 'yara'}:
            prefix = 'Y' if finding['source_type'] == 'yara' else 'F'
            counters[prefix] += 1
            finding['id'] = f'{prefix}-{counters[prefix]:03d}'
        else:
            finding['id'] = 'MON-' + hashlib.sha256(identity.encode()).hexdigest()[:24]
        findings.append(finding)
    return findings


def laptop_source_coverage(scan):
    """Missing data is coverage information, never a fabricated finding."""
    coverage = []
    def add(source, available, error=None, partial=False, note=''):
        status = 'unavailable' if error else 'not recorded' if not available else 'partial' if partial else 'recorded'
        detail = error or note
        coverage.append(dict(source=source, status=status,
                             detail=_canonical(detail) if isinstance(detail, (dict, list)) else str(detail)))
    add('filesystem', isinstance(scan.get('findings'), list), partial=not scan.get('scan_complete', False),
        note=f"{scan.get('files_checked', 'Unknown')} files checked; {scan.get('files_skipped', 'Unknown')} skipped. "
             'Coverage is limited to accessible supported files and configured scan limits.')
    add('yara', bool(scan.get('yara_available')), error=None if scan.get('yara_available') else 'YARA was unavailable or its availability was not recorded.')
    defender = scan.get('defender_status') or {}
    add('defender', bool(defender), scan.get('defender_status_error'),
        partial=bool(defender.get('errors') or defender.get('truncated') or not isinstance(defender.get('detections'), list)),
        note='Bounded Defender detection-history query. ' + (_canonical(defender['errors']) if defender.get('errors') else ''))
    add('process', isinstance(scan.get('running_processes'), list), scan.get('process_inventory_error'),
        partial=bool(scan.get('process_inventory_truncated')),
        note='Only processes flagged during the bounded inventory are findings.')
    startup = scan.get('startup_inventory') or {}
    add('startup and scheduled tasks', isinstance(scan.get('startup_inventory'), dict), scan.get('startup_inventory_error'),
        partial=bool(startup.get('errors') or startup.get('truncated') or
                     not all(isinstance(startup.get(k), list) for k in ('flagged_startup_items', 'flagged_scheduled_tasks'))),
        note='Bounded startup/task inventory. ' + (_canonical(startup['errors']) if startup.get('errors') else ''))
    events = scan.get('security_events') or {}
    add('windows event', isinstance(events.get('events'), list), scan.get('security_event_error'),
        partial=bool(events.get('errors') or events.get('truncated')),
        note='Retained events from the bounded query; normal events are not findings. ' + (_canonical(events['errors']) if events.get('errors') else ''))
    return coverage


def laptop_coverage_text(scan):
    lines = ['## Laptop Scan Coverage',
             'File findings require current hash verification at export. System observations are recorded snapshots, not immutable forensic artifacts.']
    for item in laptop_source_coverage(scan):
        lines.append(f"- {item['source']}: {item['status']}. {item['detail']}")
    return '\n'.join(lines) + '\n\n'


def laptop_event_references(findings):
    return [dict(log=e.get('log'), event_id=f.get('event_id'), record_id=f.get('record_id'),
                 time_utc=e.get('timestamp'), finding_id=f['id'], computer=e.get('computer'))
            for f in findings if f['source_type'] == 'windows event' for e in f['evidence']]
