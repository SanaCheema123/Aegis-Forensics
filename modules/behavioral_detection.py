"""Shared bounded, replay-safe login correlation for batch and live consumers.

Event-time retention permits late arrivals within the retained horizon. Older
arrivals are explicitly reported as incomplete coverage. No missing identities
are filled in from other events.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json

import pandas as pd

from modules.windows_security import normalize_security_event
from modules.event_timestamps import parse_timestamp, resolve_event_timestamp


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def normalize(raw):
    def clean(value):
        text = str(value or '').strip()
        return '' if text.casefold() in {'-', 'nan', 'none', 'null', 'n/a'} else text
    windows = normalize_security_event(raw) if 'EventId' in raw else raw
    if 'aegis_timestamp_status' in raw:
        resolved = parse_timestamp(raw.get('aegis_timestamp_utc'))
        if raw.get('aegis_timestamp_status') != 'resolved':
            return None
    else:
        _, resolved = resolve_event_timestamp(windows)
    if resolved.utc is None:
        return None
    stamp = resolved.utc
    try:
        event_id = int(windows.get('EventId', windows.get('event_id', 0)))
    except (ValueError, TypeError):
        return None
    account = clean(windows.get('account') or windows.get('user')).casefold()
    # Never substitute SubjectUserName for a missing logon target.
    if 'EventId' in raw and isinstance(raw.get('EventData'), dict):
        data = {k.casefold(): v for k, v in raw['EventData'].items()}
        target = clean(data.get('targetusername'))
        domain = clean(data.get('targetdomainname'))
        account = ((domain + '\\' if domain and domain != '.' and '\\' not in target else '') + target).casefold() if target else ''
    ip = clean(windows.get('source_ip')).casefold()
    try:
        address = ipaddress.ip_address(ip)
        ip = str(getattr(address, 'ipv4_mapped', None) or address)
    except ValueError:
        pass
    host = clean(windows.get('Computer') or windows.get('MachineName') or windows.get('host')).casefold()
    evidence = {**dict(raw), "timestamp_original": raw.get("aegis_timestamp_original", windows.get("TimestampOriginal", resolved.original)),
                "timestamp_utc": resolved.text, "timestamp_status": resolved.status}
    # Location-independent Windows identity; CSV records without native IDs use content.
    record = windows.get('RecordId', windows.get('record_id'))
    identity = [host, windows.get('Log', ''), record, event_id, stamp.isoformat(), windows.get('Fingerprint', '')]
    if not record:
        identity += [account, ip, windows.get('message', windows.get('Message', ''))]
    return dict(uid=digest(identity), timestamp=stamp.isoformat(), event_id=event_id,
                account=account, source_ip=ip, host=host, evidence=evidence)


class BehavioralDetector:
    def __init__(self, failed_threshold=5, window_minutes=10, success_window_minutes=30,
                 max_events=10000, state=None):
        if failed_threshold < 1 or min(window_minutes, success_window_minutes) <= 0 or max_events < 1:
            raise ValueError('Behavioral thresholds and bounds must be positive')
        self.threshold = failed_threshold
        self.window = timedelta(minutes=window_minutes)
        self.success_window = timedelta(minutes=success_window_minutes)
        self.max_events = max_events
        self.state = state or {'events': [], 'emitted': {}, 'watermark': None}
        self.diagnostics = []

    def export_state(self):
        return self.state

    def feed(self, records, now=None):
        self.diagnostics = []
        events = {}
        invalid_cached = False
        for cached in self.state['events']:
            source = cached.get('evidence')
            event = normalize(source) if isinstance(source, dict) else None
            if event is None:
                invalid_cached = True
                continue
            events[event['uid']] = event
        if invalid_cached:
            self.diagnostics.append('Cached events with unresolved source timestamps were excluded; their watermark is not chronological evidence.')
            allowed = {'behavior-' + digest([rule, event['uid']]) for event in events.values()
                       for rule in ('Brute force login attempts', 'Successful login after brute force')}
            self.state = dict(events=list(events.values()),
                emitted={key: value for key, value in self.state['emitted'].items() if key in allowed},
                bursts=[], watermark=max((e['timestamp'] for e in events.values()), default=None))
        watermark = self.state['watermark']
        for raw in records:
            event = normalize(raw)
            if event is None:
                self.diagnostics.append('Insufficient event context: missing or invalid timestamp/event ID.')
                continue
            if event['event_id'] not in (4624, 4625):
                continue
            if not event['source_ip']:
                self.diagnostics.append('Insufficient event context: source IP missing; login correlation skipped.')
                continue
            if not event['account']:
                self.diagnostics.append('Insufficient event context: account missing; success correlation unavailable.')
            if not event['host']:
                self.diagnostics.append('Insufficient event context: host missing; correlation limited to records without host context.')
            events[event['uid']] = event
            watermark = max(watermark or event['timestamp'], event['timestamp'])
        if not watermark:
            return []
        cutoff = (pd.Timestamp(watermark) - self.window - self.success_window).isoformat()
        previous = self.state['watermark']
        previous_cutoff = (pd.Timestamp(previous) - self.window - self.success_window).isoformat() if previous else ''
        retained = sorted((e for e in events.values() if e['timestamp'] >= previous_cutoff), key=lambda e: (e['timestamp'], e['uid']))
        if len(retained) != len(events):
            self.diagnostics.append('Late events outside the retained correlation horizon cannot be correlated.')
        if len(retained) > self.max_events:
            self.diagnostics.append('Behavioral state capacity reached; oldest context discarded. Coverage is incomplete.')
        retained = retained[-self.max_events:]
        emitted = dict(self.state['emitted'])
        bursts = [dict(b) for b in self.state.get('bursts', [])]
        groups = defaultdict(list)
        for event in retained:
            groups[(event['host'], event['source_ip'])].append(event)
        findings = []

        def publish(rule, rows, terminal, severity, mitre):
            if terminal['event_id'] == 4625:
                scope = [terminal['host'], terminal['source_ip']]
                for burst in bursts:
                    if (burst['scope'] == scope and rows[0]['timestamp'] <= burst['end']
                            and terminal['timestamp'] >= burst['start']):
                        burst['start'] = min(burst['start'], rows[0]['timestamp'])
                        burst['end'] = max(burst['end'], terminal['timestamp'])
                        return
                bursts.append(dict(scope=scope, start=rows[0]['timestamp'], end=terminal['timestamp']))
            uid = 'behavior-' + digest([rule, terminal['uid']])
            if uid in emitted:
                return
            emitted[uid] = watermark
            evidence = [e['evidence'] for e in rows]
            findings.append(dict(detection_id=uid, source='behavioral', rule=rule,
                severity=severity, mitre=mitre, description=f'{rule}: {len(rows)} correlated events.',
                first_seen=terminal['timestamp'] if terminal['event_id'] == 4624 else rows[0]['timestamp'],
                last_seen=terminal['timestamp'], users=', '.join(sorted({e['account'] for e in rows} - {''})),
                source_ips=terminal['source_ip'], hosts=terminal['host'], event_count=len(rows),
                evidence=evidence, detection_metadata=dict(failed_threshold=self.threshold,
                    window_seconds=self.window.total_seconds(), success_window_seconds=self.success_window.total_seconds(),
                    event_uids=[e['uid'] for e in rows], context_complete=all(e['account'] and e['host'] for e in rows))))

        for group in groups.values():
            failures = []
            compromised = set()
            for event in group:
                instant = pd.Timestamp(event['timestamp'])
                if event['event_id'] == 4625:
                    failures.append(event)
                    recent = [e for e in failures if pd.Timestamp(e['timestamp']) >= instant - self.window]
                    if len(recent) >= self.threshold:
                        publish('Brute force login attempts', recent, event, 'High', 'T1110')
                    continue
                if not event['account']:
                    continue
                candidates = [e for e in failures if
                              instant - self.window - self.success_window <= pd.Timestamp(e['timestamp']) < instant]
                for end in reversed(candidates):
                    end_time = pd.Timestamp(end['timestamp'])
                    if instant - end_time > self.success_window:
                        break
                    window = [e for e in candidates if end_time - self.window <= pd.Timestamp(e['timestamp']) <= end_time]
                    if len(window) >= self.threshold and any(e['account'] == event['account'] for e in window):
                        key = (event['account'], end['uid'])
                        if key not in compromised:
                            publish('Successful login after brute force', window + [event], event, 'Critical', 'T1110, T1078')
                            compromised.add(key)
                        break
        # Both retained input and suppression state have explicit bounds.
        if now is not None:
            watermark = max(watermark, now.astimezone(timezone.utc).isoformat())
        cutoff = (pd.Timestamp(watermark) - self.window - self.success_window).isoformat()
        self.state = dict(events=[e for e in retained if e['timestamp'] >= cutoff],
                          emitted=dict([(k, v) for k, v in emitted.items() if v >= cutoff][-self.max_events * 2:]),
                          bursts=[b for b in bursts if b['end'] >= cutoff][-self.max_events:],
                          watermark=watermark)
        self.diagnostics = list(dict.fromkeys(self.diagnostics))
        return findings


def detect_batch(records, **options):
    detector = BehavioralDetector(**options)
    findings = detector.feed(records)
    return findings, detector.diagnostics
