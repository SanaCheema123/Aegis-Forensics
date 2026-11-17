import pandas as pd
import json
import os
from modules.csv_evidence import read_evidence_csv

class LogParser:
    def __init__(self, file_path: str):
        self.file_path = file_path

    def parse_logs(self) -> pd.DataFrame:
        """Parses uploaded evidence files (CSV or JSON) into a standardized DataFrame."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Evidence file not found at: {self.file_path}")
        
        file_extension = os.path.splitext(self.file_path)[1].lower()

        if file_extension == '.csv':
            df = read_evidence_csv(self.file_path)
        elif file_extension == '.json':
            df = pd.read_json(self.file_path)
        else:
            # Fallback for plain text or log files
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            df = pd.DataFrame({'raw_log': [line.strip() for line in lines]})

        return df