import json, urllib.request
import sys

url = "https://api.github.com/repos/jaimeehd/personal-mcp/actions/runs?per_page=3&branch=main"
req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "python"})
data = json.loads(urllib.request.urlopen(req).read())
for r in data.get("workflow_runs", [])[:3]:
    run_id = r["id"]
    jurl = f"https://api.github.com/repos/jaimeehd/personal-mcp/actions/runs/{run_id}/jobs"
    jreq = urllib.request.Request(jurl, headers={"Accept": "application/vnd.github+json", "User-Agent": "python"})
    jdata = json.loads(urllib.request.urlopen(jreq).read())
    print(f"Run {run_id} | {r['display_title'][:60]:60s} | {r['status']:12s} | {r.get('conclusion') or 'running'}")
    for job in jdata.get("jobs", []):
        ok = "OK" if job.get("conclusion") == "success" else "FAIL" if job.get("conclusion") == "failure" else "WAIT" if job.get("status") == "in_progress" else "SKIP"
        print(f"  [{ok:4s}] {job['name']} | {job.get('conclusion') or job['status']}")
    print()
