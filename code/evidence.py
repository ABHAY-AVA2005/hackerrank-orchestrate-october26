"""
Evidence indexing and point-in-time state inspector.
Parses evidence files (.sql, .json, .log, .txt, .pdf) and matches point-in-time evidence to requests.
"""
import base64
import csv
import json
import os
import re
import zlib
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

class EvidenceManager:
    def __init__(self, evidence_files_csv: str, evidence_dir: str):
        self.evidence_files_csv = evidence_files_csv
        self.evidence_dir = evidence_dir
        self.files: List[dict] = []
        self.file_by_id: Dict[str, dict] = {}
        
        with open(evidence_files_csv, 'r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                r['captured_at_dt'] = datetime.fromisoformat(r['captured_at'].replace('Z', '+00:00'))
                self.files.append(r)
                self.file_by_id[r['file_id']] = r

    def get_candidate_evidence_files(self, audit_at_str: str) -> List[dict]:
        """Returns evidence files captured at or immediately prior to audit_at."""
        audit_dt = datetime.fromisoformat(audit_at_str.replace('Z', '+00:00'))
        candidates = []
        for f in self.files:
            diff = (audit_dt - f['captured_at_dt']).total_seconds()
            # Strictly enforce temporal cutoff: only evidence captured at or before audit_at
            if diff >= 0:
                candidates.append((abs(diff), f))
        candidates.sort(key=lambda x: x[0])
        return [c[1] for c in candidates]

    def _read_pdf_file(self, full_path: str) -> str:
        try:
            with open(full_path, 'rb') as f:
                data = f.read()
            texts = []
            idx = 0
            while True:
                s_idx = data.find(b'stream', idx)
                if s_idx == -1: break
                e_idx = data.find(b'endstream', s_idx)
                if e_idx == -1: break
                content_start = s_idx + 6
                if data[content_start:content_start+2] == b'\r\n': content_start += 2
                elif data[content_start:content_start+1] == b'\n': content_start += 1
                raw = data[content_start:e_idx].strip()
                idx = e_idx + 9
                for method in ['a85', 'raw']:
                    try:
                        b = base64.a85decode(raw, adobe=True) if method == 'a85' else raw
                        decomp = zlib.decompress(b)
                        s = decomp.decode('latin1', errors='ignore')
                        for tj in re.findall(r'\((.*?)\)\s*Tj', s):
                            texts.append(tj)
                    except Exception:
                        pass
            return ' '.join(texts)
        except Exception:
            return ""

    def read_file_content(self, file_id: str) -> str:
        """Reads content of an evidence file."""
        if file_id not in self.file_by_id:
            return ""
        rel_path = self.file_by_id[file_id]['file_path']
        full_path = os.path.join(self.evidence_dir, rel_path)
        if not os.path.exists(full_path):
            full_path = os.path.join(os.path.dirname(self.evidence_dir), rel_path)
        if not os.path.exists(full_path):
            return ""
        if full_path.endswith('.pdf'):
            return self._read_pdf_file(full_path)
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ""
