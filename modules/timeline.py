"""Verified event chronology with unresolved records kept separately."""
import hashlib
import json

import pandas as pd
from modules.csv_evidence import source_locator
from modules.event_timestamps import select_timestamp_column


class TimelineConstructor:
    def __init__(self, df: pd.DataFrame):
        self.df = df
        self.selection = {}
        self.unresolved_events = pd.DataFrame()

    def build_timeline(self, timestamp_column=None) -> pd.DataFrame:
        self.selection = select_timestamp_column(self.df, timestamp_column)
        frame = self.df.copy()
        locators = [source_locator(self.df, index, position=position)
                    for position, index in enumerate(self.df.index)]
        for field in ('record_number', 'line', 'line_end', 'csv_record_id', 'sha256'):
            frame['source_' + field] = [locator.get(field) for locator in locators]
        values = self.selection['values']
        frame['aegis_timestamp_column'] = self.selection['column']
        frame['aegis_timestamp_original'] = [v.original for v in values] if values else None
        frame['aegis_timestamp_utc'] = pd.array([v.utc for v in values] if values else [None] * len(frame), dtype='datetime64[ns, UTC]')
        frame['aegis_timestamp_status'] = [v.status for v in values] if values else self.selection['status']
        resolved = frame['aegis_timestamp_status'].eq('resolved')
        self.unresolved_events = frame.loc[~resolved].copy()
        if not resolved.any():
            return frame.iloc[0:0].copy()
        # Equal instants use source identities, not arrival order.
        def tie(row, locator):
            digest = hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
            native = row.get('RecordId', row.get('record_id'))
            if native is not None:
                return str(row.get('Computer', row.get('host', ''))) + ':' + str(row.get('Log', '')) + ':' + str(native).zfill(24) + ':' + digest
            if locator.get('csv_record_id'):
                return locator.get('sha256', '') + ':' + locator.get('file', '') + ':' + str(locator['record_number']).zfill(24)
            return digest
        keys = [tie(row.to_dict(), locator) if resolved.iloc[position] else ''
                for position, ((_, row), locator) in enumerate(zip(self.df.iterrows(), locators))]
        order = pd.DataFrame({'utc': frame['aegis_timestamp_utc'].array, 'tie': keys})
        positions = order.loc[resolved.to_numpy()].sort_values(['utc', 'tie'], kind='stable').index
        return frame.iloc[positions].copy()
