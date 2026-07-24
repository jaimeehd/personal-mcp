import json, urllib.request, sys

run_id = sys.argv[1]

# Get the job list
jurl = f"https://api.github.com/repos/jaimeehd/personal-mcp/actions/runs/{run_id}/jobs"
jreq = urllib.request.Request(jurl, headers={"Accept": "application/vnd.github+json", "User-Agent": "python"})
jdata = json.loads(urllib.request.urlopen(jreq).read())

# Find the failed job
for job in jdata.get("jobs", []):
    if job.get("conclusion") != "failure":
        continue
    job_id = job["id"]
    print(f"Job: {job['name']} (id={job_id})")
    
    # Try the raw log URL
    # https://github.com/jaimeehd/personal-mcp/actions/runs/{run_id}/attempts/1/jobs/{job_id}
    log_url = f"https://github.com/jaimeehd/personal-mcp/actions/runs/{run_id}/attempts/1/jobs/{job_id}"
    print(f"Log URL: {log_url}")
    log_req = urllib.request.Request(log_url, headers={
        "Accept": "text/html,application/xhtml+xml",
        "User-Agent": "Mozilla/5.0"
    })
    try:
        resp = urllib.request.urlopen(log_req)
        content = resp.read().decode("utf-8")
        # Find the text content in the page
        print(content[:3000])
    except Exception as e:
        print(f"Error: {e}")
    print()
