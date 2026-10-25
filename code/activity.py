"""
System activity auditor.
Indexes recorded system activities and deletion worker events.
"""
import csv
from datetime import datetime
from typing import Dict, List, Optional, Set

class ActivityAuditor:
    def __init__(self, system_activity_path: str):
        self.activities: List[dict] = []
        self.resource_activities: Dict[str, List[dict]] = {}
        
        with open(system_activity_path, 'r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                self.activities.append(r)
                rid = r['resource_id']
                if rid:
                    self.resource_activities.setdefault(rid, []).append(r)

    def get_activities_for_resource(self, resource_id: str) -> List[dict]:
        return self.resource_activities.get(resource_id, [])

    def get_deletion_worker_activities(self) -> List[dict]:
        return [a for a in self.activities if a['source_system'] == 'deletion_worker']
