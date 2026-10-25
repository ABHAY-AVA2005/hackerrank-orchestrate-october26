# -*- coding: utf-8 -*-
import csv, json, sys, os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "code"))

from auditor import DeletionAuditor

DATASET = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")

with open(os.path.join(DATASET, "sample_deletion_requests.csv"), encoding="utf-8", errors="replace") as f:
    reqs = list(csv.DictReader(f))

with open(os.path.join(DATASET, "sample_output.csv"), encoding="utf-8", errors="replace") as f:
    expected = {r["case_id"]: r for r in csv.DictReader(f)}

auditor = DeletionAuditor(DATASET)

def normalize(steps):
    return sorted([
        (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])
        for s in steps
    ])

status_hits = 0
step_hits = 0
mismatches = []

for req in reqs:
    cid = req["case_id"]
    got_status, got_steps = auditor.audit_case(req)
    exp_row = expected[cid]
    exp_status = exp_row["deletion_status"]
    exp_steps = json.loads(exp_row["steps_json"])

    ok_status = got_status == exp_status
    ok_steps = normalize(got_steps) == normalize(exp_steps)

    if ok_status: status_hits += 1
    if ok_steps:  step_hits  += 1
    else:
        mismatches.append((cid, got_status, exp_status, got_steps, exp_steps))

print("\n=== METRICS ===")
print("Status Accuracy : {}/{} ({:.1f}%)".format(status_hits, 32, 100*status_hits/32))
print("Exact Step Match: {}/{} ({:.1f}%)".format(step_hits, 32, 100*step_hits/32))
print("\n=== MISMATCHES ({}) ===\n".format(len(mismatches)))

for cid, got_st, exp_st, got, exp in mismatches:
    status_ok = "OK" if got_st == exp_st else "FAIL"
    print("---- {} status:{} got={} exp={} ----".format(cid, status_ok, got_st, exp_st))
    got_n = normalize(got)
    exp_n = normalize(exp)
    only_got = [x for x in got_n if x not in exp_n]
    only_exp = [x for x in exp_n if x not in got_n]
    if only_got:
        print("  EXTRA (we have, GT does not):")
        for x in only_got:
            print("    + {}".format(x))
    if only_exp:
        print("  MISSING (GT has, we do not):")
        for x in only_exp:
            print("    - {}".format(x))
    print()