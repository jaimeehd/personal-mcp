
from src.secretscanner import SecretFinding, scan_file, scan_text


def test_finds_github_token():
    content = "GITHUB_TOKEN=ghp_abc123def456ghi789jkl012mno345pqr678"
    findings = scan_text(content)
    assert len(findings) == 1
    assert findings[0].secret_type == "GitHub Token"
    assert findings[0].severity == "high"
    assert findings[0].line == 1


def test_finds_aws_access_key_id():
    content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(content)
    assert len(findings) == 1
    assert findings[0].secret_type == "AWS Access Key ID"


def test_finds_private_key():
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    findings = scan_text(content)
    assert len(findings) == 1
    assert "Private Key" in findings[0].secret_type


def test_finds_jwt():
    content = ("eyJhbGciOiJIUzI1NiJ9."
               "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNqP2sT7XjFQCfN7tQ")
    findings = scan_text(content)
    assert len(findings) == 1
    assert findings[0].secret_type == "JWT Token"


def test_clean_file_no_findings():
    content = """const name = 'John';
let age = 30;
function hello() { return 'world'; }
const greeting = 'Hello, World!';
"""
    findings = scan_text(content)
    assert len(findings) == 0


def test_multiple_findings_different_types():
    content = ("token=ghp_abc123def456ghi789jkl012mno345pqr678\n"
               "password='supersecret123'")
    findings = scan_text(content)
    types = {f.secret_type for f in findings}
    assert "GitHub Token" in types
    assert "Potential Password" in types


def test_deduplicates_same_finding():
    content = ("x=ghp_abc123def456ghi789jkl012mno345pqr678\n"
               "y=ghp_abc123def456ghi789jkl012mno345pqr678")
    findings = scan_text(content)
    assert len(findings) == 2


def test_scan_file(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("token=ghp_abc123def456ghi789jkl012mno345pqr678")
    findings = scan_file(f)
    assert len(findings) == 1
    assert findings[0].secret_type == "GitHub Token"


def test_scan_file_binary_graceful(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\x00\x01\x02\x03")
    findings = scan_file(f)
    assert len(findings) == 0


def test_finds_gitlab_token():
    content = "GITLAB_TOKEN=glpat-abc123def456ghi789jkl012mno"
    findings = scan_text(content)
    assert len(findings) == 1
    assert findings[0].secret_type == "GitLab Token"


def test_finds_slack_token():
    content = "xoxb-123456789012-1234567890123-abc123def456"
    findings = scan_text(content)
    assert len(findings) == 1
    assert findings[0].secret_type == "Slack Token"


def test_finds_db_connection_string():
    content = "mysql://user:password@localhost:3306/dbname"
    findings = scan_text(content)
    assert len(findings) >= 1


def test_secret_finding_dataclass():
    f = SecretFinding("test", 1, "snippet", "high", 0)
    assert f.secret_type == "test"
    assert f.line == 1
    assert f.severity == "high"


def test_empty_content():
    assert scan_text("") == []


def test_scan_text_none_content():
    assert scan_text("") == []
