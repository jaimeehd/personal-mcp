import json, urllib.request, sys

run_id = sys.argv[1]
jurl = f"https://api.github.com/repos/jaimeehd/personal-mcp/actions/runs/{run_id}/jobs"
jreq = urllib.request.Request(jurl, headers={"Accept": "application/vnd.github+json", "User-Agent": "python"})
jdata = json.loads(urllib.request.urlopen(jreq).read())

# Find the failed job and check failure steps
for job in jdata.get("jobs", []):
    if job.get("conclusion") != "failure":
        continue
    print(f"== JOB: {job['name']} ==")
    for step in job.get("steps", []):
        if step.get("conclusion") == "failure":
            print(f"FAILED STEP: {step['name']}")
            # Try annotations
            print(f"  number: {step['number']}")
    # Try getting check runs / annotations
    print()
