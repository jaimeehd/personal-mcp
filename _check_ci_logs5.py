import json, urllib.request, sys

run_id = sys.argv[1]
# Try getting raw logs for the run directly
url = f"https://api.github.com/repos/jaimeehd/personal-mcp/actions/runs/{run_id}/logs"
req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "python"})
try:
    resp = urllib.request.urlopen(req)
    data = resp.read()
    print(f"Logs downloaded ({len(data)} bytes)")
    print(data.decode("utf-8")[-5000:])
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}: {e.reason}")
    # Try alternative: the log archive URL
    alt_url = f"https://github.com/jaimeehd/personal-mcp/actions/runs/{run_id}/logs"
    print(f"Try: {alt_url}")
    # Or try the raw text download
    # https://github.com/jaimeehd/personal-mcp/actions/runs/{run_id}/attempts/1
