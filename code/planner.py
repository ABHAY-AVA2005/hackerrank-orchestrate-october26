"""
Execution and verification plan generator.
Orders steps strictly per the competition deterministic tie-breaker specification:
1. Phase Order: FINDING -> REMEDIATION -> VERIFICATION
2. Operation Order:
   - Finding: REPORT_REMAINING_RECORD -> REPORT_EXPOSED_PII -> REPORT_ACTIVE_DATA_FLOW -> REPORT_RESTORE_RISK
   - Remediation: DISABLE_DATA_FLOW -> BLOCK_RESTORE -> DELETE_RECORD -> REDACT_RECORD -> ANONYMIZE_RECORD
   - Verification: VERIFY_RECORD_ABSENT -> VERIFY_RECORD_PRESENT -> VERIFY_RECORD_REDACTED -> VERIFY_RECORD_ANONYMIZED -> VERIFY_DATA_FLOW_DISABLED -> VERIFY_RESTORE_BLOCKED
3. Secondary Sort: system_id (alphabetical)
4. Tertiary Sort: resource_id (alphabetical)
"""
from typing import Dict, List

PHASE_ORDER = {
    'FINDING': 0,
    'REMEDIATION': 1,
    'VERIFICATION': 2
}

OP_ORDER = {
    # Findings
    'REPORT_REMAINING_RECORD': 0,
    'REPORT_EXPOSED_PII': 1,
    'REPORT_ACTIVE_DATA_FLOW': 2,
    'REPORT_RESTORE_RISK': 3,
    # Remediation
    'DISABLE_DATA_FLOW': 0,
    'BLOCK_RESTORE': 1,
    'DELETE_RECORD': 2,
    'REDACT_RECORD': 3,
    'ANONYMIZE_RECORD': 4,
    # Verification
    'VERIFY_RECORD_ABSENT': 0,
    'VERIFY_RECORD_PRESENT': 1,
    'VERIFY_RECORD_REDACTED': 2,
    'VERIFY_RECORD_ANONYMIZED': 3,
    'VERIFY_DATA_FLOW_DISABLED': 4,
    'VERIFY_RESTORE_BLOCKED': 5
}

class PlanGenerator:
    @staticmethod
    def sort_and_number_steps(steps: List[dict]) -> List[dict]:
        """
        Sorts raw step definitions and applies 1-based sequential step numbers.
        """
        def sort_key(s):
            phase_val = PHASE_ORDER.get(s.get('phase', ''), 99)
            op_val = OP_ORDER.get(s.get('operation', ''), 99)
            sys_val = str(s.get('system_id') or '')
            res_val = str(s.get('resource_id') or '')
            return (phase_val, op_val, sys_val, res_val)

        sorted_steps = sorted(steps, key=sort_key)
        numbered_steps = []
        for idx, s in enumerate(sorted_steps, 1):
            numbered_steps.append({
                "step_no": idx,
                "phase": str(s.get('phase') or ''),
                "system_id": str(s.get('system_id') or ''),
                "resource_id": str(s.get('resource_id') or ''),
                "operation": str(s.get('operation') or ''),
                "state": str(s.get('state') or ''),
                "evidence_id": str(s.get('evidence_id') or '')
            })
        return numbered_steps
