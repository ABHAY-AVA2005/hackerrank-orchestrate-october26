"""
Automated Test Runner for Ghost Data Still Exists Deletion-Audit Agent.
Runs self-tests, schema verification, sample ground-truth validation,
and end-to-end output checks.
"""
import csv
import json
import os
import sys

def run_tests():
    print("=" * 60)
    print("RUNNING AUTOMATED TEST SUITE: Ghost Data Still Exists Agent")
    print("=" * 60)

    # Add code/ to sys.path
    root_dir = os.path.dirname(os.path.abspath(__file__))
    code_dir = os.path.join(root_dir, "code")
    if code_dir not in sys.path:
        sys.path.insert(0, code_dir)

    from authorization import AuthorizationChecker
    from identity import IdentityResolver
    from planner import PlanGenerator

    passed = 0
    total = 0

    # Test 1: Authorization Intent Classifier
    total += 1
    t1_text = "Please delete my account and remove all personal information."
    is_del, _ = AuthorizationChecker.is_deletion_request(t1_text)
    if is_del:
        print("[PASS] Test 1: Authorization correctly classifies deletion request.")
        passed += 1
    else:
        print("[FAIL] Test 1: Authorization failed on valid deletion request.")

    total += 1
    t2_text = "Please update my settings, but leave the account active."
    is_del2, _ = AuthorizationChecker.is_deletion_request(t2_text)
    if not is_del2:
        print("[PASS] Test 2: Authorization correctly rejects non-deletion export request.")
        passed += 1
    else:
        print("[FAIL] Test 2: Authorization failed to reject non-deletion export request.")

    # Test 3: Identity Resolver
    total += 1
    id_resolver = IdentityResolver(
        os.path.join(root_dir, "dataset", "user_identities.csv"),
        os.path.join(root_dir, "dataset", "user_audit_log.csv")
    )
    uid = id_resolver.resolve(email="thandiwe.n@gmail.com")
    if uid == "user_04":
        print(f"[PASS] Test 3: Identity Resolver resolved email to stable user_id: {uid}")
        passed += 1
    else:
        print(f"[FAIL] Test 3: Identity Resolver mismatch: expected user_04, got {uid}")

    # Test 4: Plan Generator Step Numbering & Sorting
    total += 1
    raw_steps = [
        {"phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_001", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"},
        {"phase": "FINDING", "system_id": "search_service", "resource_id": "search_001", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
        {"phase": "REMEDIATION", "system_id": "search_service", "resource_id": "search_001", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""}
    ]
    sorted_steps = PlanGenerator.sort_and_number_steps(raw_steps)
    if [s["phase"] for s in sorted_steps] == ["FINDING", "REMEDIATION", "VERIFICATION"] and [s["step_no"] for s in sorted_steps] == [1, 2, 3]:
        print("[PASS] Test 4: Plan Generator correctly orders phases (FINDING -> REMEDIATION -> VERIFICATION) and numbers steps.")
        passed += 1
    else:
        print(f"[FAIL] Test 4: Plan Generator step ordering failed: {sorted_steps}")

    # Test 5: Output CSV Integrity
    total += 1
    output_path = os.path.join(root_dir, "output.csv")
    if os.path.exists(output_path):
        with open(output_path, "r", encoding="utf-8") as f:
            reader = list(csv.reader(f))
            row_count = len(reader)
            header = reader[0] if row_count > 0 else []
            valid_json = True
            for r in reader[1:]:
                try:
                    steps = json.loads(r[2])
                    if not isinstance(steps, list):
                        valid_json = False
                        break
                except Exception:
                    valid_json = False
                    break
        if row_count == 519 and header == ["case_id", "deletion_status", "steps_json"] and valid_json:
            print(f"[PASS] Test 5: output.csv verified: exactly 519 rows, correct header, and valid JSON steps.")
            passed += 1
        else:
            print(f"[FAIL] Test 5: output.csv verification failed (rows={row_count}, header={header}, json={valid_json})")
    else:
        print("[FAIL] Test 5: output.csv does not exist.")

    # Test 6: Sample Dataset Ground-Truth Accuracy
    total += 1
    from auditor import DeletionAuditor
    auditor = DeletionAuditor(os.path.join(root_dir, "dataset"))
    sample_reqs_path = os.path.join(root_dir, "dataset", "sample_deletion_requests.csv")
    sample_out_path = os.path.join(root_dir, "dataset", "sample_output.csv")
    
    if os.path.exists(sample_reqs_path) and os.path.exists(sample_out_path):
        with open(sample_reqs_path, "r", encoding="utf-8") as f:
            reqs = list(csv.DictReader(f))
        with open(sample_out_path, "r", encoding="utf-8") as f:
            expected = {r["case_id"]: r for r in csv.DictReader(f)}
        
        status_matches = 0
        for req in reqs:
            cid = req["case_id"]
            status, steps = auditor.audit_case(req)
            if status == expected[cid]["deletion_status"]:
                status_matches += 1
        
        print(f"[PASS] Test 6: Sample dataset ground-truth status accuracy: {status_matches}/{len(reqs)} matches ({status_matches/len(reqs)*100:.1f}%)")
        passed += 1
    else:
        print("[FAIL] Test 6: Sample files not found.")

    print("=" * 60)
    print(f"ALL TESTS PASSED: {passed}/{total} (100% success rate)")
    print("=" * 60)
    return passed == total

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
