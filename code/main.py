"""
Main entry point and CLI runner for the Deletion-Audit Agent.
Processes deletion requests and produces compliant output CSV.
"""
import argparse
import csv
import json
import os
import argparse
import csv
import json
import os
import sys

# Add parent directory to sys.path so imports work seamlessly
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from auditor import DeletionAuditor


def run_auditor(requests_csv: str, dataset_dir: str, output_csv: str):
    print(f"Initializing DeletionAuditor with dataset at {dataset_dir}...")
    auditor = DeletionAuditor(dataset_dir)
    
    print(f"Reading deletion requests from {requests_csv}...")
    with open(requests_csv, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        requests = list(reader)
    print(f"Loaded {len(requests)} cases to audit.")

    results = []
    status_counts = {}
    for req in requests:
        case_id = req['case_id']
        status, steps = auditor.audit_case(req)
        status_counts[status] = status_counts.get(status, 0) + 1
        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": json.dumps(steps, separators=(',', ':'))
        })

    # Sort results strictly by numeric case_id
    def case_sort_key(r):
        try:
            return int(r['case_id'].split('_')[1])
        except Exception:
            return r['case_id']

    results.sort(key=case_sort_key)

    print(f"Writing audit output to {output_csv}...")
    with open(output_csv, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        writer.writeheader()
        writer.writerows(results)

    print(f"Successfully audited {len(results)} cases.")
    print("Status distribution:", status_counts)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="HackerRank Orchestrate Deletion-Audit Agent")
    parser.add_argument('--requests', default='dataset/deletion_requests.csv', help='Path to deletion requests CSV')
    parser.add_argument('--dataset', default='dataset', help='Path to dataset directory')
    parser.add_argument('--output', default='output.csv', help='Path to output CSV file')
    args = parser.parse_args()

    run_auditor(args.requests, args.dataset, args.output)
