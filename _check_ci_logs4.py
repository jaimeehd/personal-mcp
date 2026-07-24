import json, urllib.request, sys, re

run_id = sys.argv[1]
jurl = f"https://api.github.com/repos/jaimeehd/personal-mcp/actions/runs/{run_id}/jobs"
jreq = urllib.request.Request(jurl, headers={"Accept": "application/vnd.github+json", "User-Agent": "python"})
jdata = json.loads(urllib.request.urlopen(jreq).read())

for job in jdata.get("jobs", []):
    if job.get("conclusion") != "failure":
        continue
    job_name = job["name"]
    print(f"=== {job_name} ===")
    # Get runner_name from steps
    for step in job.get("steps", []):
        if step.get("conclusion") == "failure":
            step_number = step["number"]
            print(f"Failed step {step_number}: {step['name']}")
    # Try to get logs via the job ID and build URL
    # The logs are at: https://github.com/jaimeehd/personal-mcp/actions/runs/{run_id}/job/{job_id}
    job_id = job["id"]
    print(f"Job page: https://github.com/jaimeehd/personal-mcp/actions/runs/{run_id}/job/{job_id}")
    print()
