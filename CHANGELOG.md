# Changelog

## [1.4.14] — 2026-07-07

### Security (fixed — closes the gap tracked since 1.4.10)
- **Implemented the HMAC-confirm-code design (Opción C) for `fs_approve`**, closing the caller-identity gap documented in 1.4.10 and re-confirmed unavoidable via `elicitation` in 1.4.13 (the connected client doesn't declare that capability).
- **`src/permissions.py`**: `PermissionManager` now generates a 32-byte secret (`secrets.token_bytes(32)`) in memory at construction time, never persisted to disk or exposed via any tool. `PermissionTicket` gained a `confirm_code` field (6-digit, derived from `hmac.new(secret, ticket_id, sha256)` at request time via `_generate_confirm_code()`). `approve()` now requires `confirm_code` and rejects the call via `hmac.compare_digest()` if missing or incorrect, returning `(False, "Invalid or missing confirmation code.")` without touching ticket state.
- **`src/confirm_popup.py` (new module)**: `show_confirmation_code(resource, operation, code)` displays the code via a native Windows `MessageBoxW`, launched in a daemon thread so it doesn't block the server's asyncio event loop while waiting for the user. This is the only channel where the code is visible — it is never returned in any tool response (`fs_request_allow`, `security_pending`, etc.). No-ops under pytest (`PYTEST_CURRENT_TEST` env var) to avoid blocking the suite with real popups.
- **`src/layers/layer6_permissions.py`**: `fs_approve(ticket_id, confirm_code, level="single")` — `confirm_code` is now a required parameter. `fs_request_allow`'s returned message updated to state explicitly that the confirmation code is shown on-screen and is not visible to the calling agent.
- **Tests**: `tests/test_permissions.py` and `tests/test_integration_tool_flow.py` updated — every `approve()`/`fs_approve()` call site now passes `ticket.confirm_code` (or the ticket's live code fetched via `pm._tickets[ticket_id].confirm_code` where the ticket object isn't already in scope). 6 call sites updated in `test_permissions.py`, 10 in `test_integration_tool_flow.py` (including the local `_make_fs_approve` closure, which now mirrors the real `layer6_permissions.py` signature exactly).
- **274 tests total, 272 pass.** 2 known pre-existing failures, unrelated to this change (see "Known gaps" below).

### Known gaps (documented, not fixed in this release)
- **The generic `Filesystem` MCP connector bypasses this entire mechanism** if enabled alongside `personal-mcp` with write access to this repo's path — it writes directly to disk with no ticket system at all. See `AGENTS.md` rule #12. No code fix is possible from this repo; it's a client-side connector configuration concern, not a `personal-mcp` bug.
- **`test_sh_exec_shell_operators_fallback`** (`tests/test_shell.py`) — `findstr` not in `allow_prefix`; pre-existing, unrelated to this change.
- **`test_fs_read_inside_allowed_no_grant_succeeds`** (`tests/test_smoke_runtime.py`) — smoke test out of sync with the "Option C" read-auto-allow behavior (v1.4.1); pre-existing, unrelated to this change.
- `pyproject.toml` version bump still outstanding (now several versions behind, tracked since 1.4.7).

## [1.4.13] — 2026-07-05

### Investigated (no code change to the permission system — see AGENTS.md rule #9)
- **Evaluated `elicitation` (standard MCP protocol mechanism for pausing a tool call to request real human confirmation via the client's UI, with no agent mediation) as an alternative to the HMAC-confirm-code design planned for the `fs_approve` caller-identity gap (1.4.10)**. Elicitation is architecturally superior *if the client supports it*: it uses the client's native UI instead of requiring a human to read a terminal, and needs no new dependency — `Context.elicit(message, schema)` is already available in the installed FastMCP version (`mcp/server/fastmcp/server.py`).
- **Isolated test tool** (`_test_elicitation`, temporary, added and removed in this same session) called `ctx.elicit()` against the connected MCP client. **Result: `McpError: Method not found`** — the client does not declare the elicitation capability at all. This is a harder failure than the known `anthropics/claude-code#56243` bug (silent auto-cancel with a rendered-then-discarded prompt); here the RPC method itself doesn't exist from the client's perspective.
- **Conclusion**: elicitation is not viable on the current client. The HMAC-confirm-code design (Opción C, still not implemented) remains the only technical path available today. Documented in `AGENTS.md` rule #9 as a sub-finding, including the exact failure mode, so a future session doesn't re-propose elicitation without first re-running this check against whatever client is connected at that time.
- **No change to `layer6_permissions.py`'s actual `fs_approve`/`fs_request_allow` behavior in this release.** The caller-identity gap remains open and exploitable exactly as described in 1.4.10 and AGENTS.md rules #9/#10 — this entry only rules out one candidate fix, it does not close the gap.

## [1.4.12] — 2026-07-05

### Added
- **Execute-approval gate for general-purpose interpreters (`approval_required_prefix`)**: `CommandPolicy.approval_required_prefix` (default: `["python", "node", "bash"]`) plus `SecurityValidator.validate_shell_execution()` (`security.py`). Rationale: `python`/`node`/`bash` are whitelisted in `allow_prefix` because legitimate dev workflows need them, but once whitelisted by prefix, anything executed *inside* the interpreter (arbitrary code via `-c`/`-e`) is invisible to `paths_allow`/`deny` — a structural limitation of prefix-based whitelisting, not a bug. This does not close that gap (nothing running inside an already-approved interpreter is contained), it adds a checkpoint before the interpreter is allowed to run at all: the first segment of a command whose first word matches `approval_required_prefix` requires an explicit `execute` ticket on the resolved interpreter path (`shutil.which(...)`) before proceeding, reusing the existing `PermissionManager`/`fs_approve` ticket flow (`operation="execute"`, already excluded from wildcard `"*"` grants — same isolation as `"delete"`). Wired into `sh_exec` and `sh_session_send` wrappers in `layer2_shell.py`. Ticket level defaults to `SINGLE` unless the approver explicitly requests `session`/`permanent` via `fs_approve`.
- **`deny` list extended (locally, not in code defaults) with interpreter-reachable dangerous primitives**: `os.system`, `subprocess.run/Popen/call`, `shutil.rmtree`, `child_process`, `require('fs').unlink`, pipe-to-shell patterns (`curl * | `, `iex (`, etc.) — modeled after Desktop Commander's `blockedCommands` denylist approach. This is a config-level addition (the operator's own `~/.personal-mcp/config.json`), not a change to `CommandPolicy.deny`'s default in `config.py` — new installs do not get these patterns automatically. `CONFIG-GUIA.md` now documents this list as a recommended starter set.

### Known gaps (not fixed in this release — documented, not silently left undiscoverable)
- **`sh_script` does not call `validate_shell_execution()`** — only `sh_exec`/`sh_session_send` do. Currently harmless because `sh_script`'s separate, stricter `readonly_prefix` whitelist (v1.4.5) does not include any general `python <file>`/`node <file>` invocation — so `sh_script` cannot reach a general-purpose interpreter today regardless. This is a latent inconsistency: if `readonly_prefix` is ever extended to include running a python/node script, `sh_script` would execute it without ever passing through the execute-approval gate, silently. Flagged for whoever touches `readonly_prefix` next.
- **Zero test coverage** for `validate_shell_execution()` — no test in `tests/` exercises the execute-ticket flow, the wildcard exclusion for `"execute"`, or the `sh_script` gap above. Checked via search before writing this entry, not assumed.
- **Does not address the caller-identity gap already tracked in `AGENTS.md` rules #9/#10 (`CHANGELOG` 1.4.10)**: this ticket flow uses the exact same `fs_approve` mechanism, with the exact same limitation — an agent can request and then approve its own `execute` ticket, since `PermissionManager.approve()` still does not verify who is calling it. Verified live in a real session: a ticket was requested for `python.EXE`, approved via `fs_approve` (by explicit human instruction in that case, not automatically), and the subsequent command was separately caught by the new `deny` pattern (`os.system`) — confirming both layers work independently, but neither closes the self-approval gap.
- `pyproject.toml` version bump still outstanding (now three versions behind, since 1.4.7).

## [1.4.11] — 2026-07-05

### Fixed
- **`project_scan`/`project_find` blocked the entire MCP connection when scanning a directory with real projects (reproduced live: 4+ minute hang, zero response)**: both functions used blocking calls directly inside `async def` — `project_scan_impl` called `subprocess.run(["git", ...], timeout=10)` twice per subdirectory (up to 20 blocking calls scanning `C:\Repos`'s ~10 projects), and `project_find_impl` called `base.rglob(filename)`, which walks the entire tree (including `node_modules`) before the exclusion filter applies. FastMCP runs all tool calls on a single shared event loop; any synchronous blocking call inside an `async def` tool freezes every other concurrent tool call for as long as it runs, not just the one in progress. This was always present, but only became reachable once `_default_project_root()` (1.4.8) started pointing at `paths_allow[0]` — previously the default silently pointed at an empty/inaccessible folder, so the loop never had real projects to hang on.
- **Fix**: extracted `_git_project_info(entry)` and `_find_files_sync(base, filename)` — plain synchronous helpers, same responsibility as before — and call them via `asyncio.to_thread()` from `project_scan_impl`/`project_find_impl`, exact same pattern already used for `fs_search` (1.4.7) for the identical class of problem. Public tool signatures (`project_scan(path=None)`, `project_find(filename, path=None)`) are unchanged.

### Notes
- Verified before changing: `tests/test_personal.py` tests the `Journal` class directly and never calls `project_scan_impl`/`project_find_impl` — zero existing test coverage for either function, so this change carries no test-compatibility risk, but also means neither function has regression coverage. Not added in this release (out of scope for the reported bug fix; flagged as debt).
- Not addressed: individual `subprocess.run()` calls remain sequential (one project at a time) rather than parallelized via `asyncio.gather` — the reported bug (blocking *other* tool calls) is fully fixed either way; parallelizing would only reduce `project_scan`'s own wall-clock time, which wasn't the complaint. Revisit if scan latency itself becomes a problem with more projects under `C:\Repos`.
- Written concurrently with another session's 1.4.10 entry below (`fs_approve` caller-identity finding) — discovered via the mandatory re-read-before-edit check; renumbered to avoid collision rather than overwriting it.
- `pyproject.toml` version bump still outstanding (noted since 1.4.7, not yet applied — now two versions behind).

## [1.4.10] — 2026-07-05

### Security (documented risk, not fixed)
- **`fs_approve` sin caller identity**: la tool `fs_approve` nunca validó quién la invoca (presente desde v1.3.0). El agente puede auto-aprobar tickets de escritura en `paths_allow`. No se implementa fix en esta versión. La solución proyectada es un Token HMAC (Opción C): clave secreta en memoria al arrancar, código HMAC impreso en stderr, `fs_approve` requiere el código como parámetro. Pendiente de implementar. Mientras tanto, AGENTS.md documenta una regla de convención (no auto-aprobar tickets) sin valor como control de seguridad.

## [1.4.9] — 2026-07-04

### Security audit findings and fixes (external audit report, verified against source before applying)
Five findings reported by an external audit pass over v1.4.8. All five verified line-by-line against actual source before any fix was applied — two severities were adjusted based on that verification (see notes).

1. **CRITICAL — Newline bypass in command segment validation (INJ-01)**: `is_command_allowed()` splits a command into segments via `split_command_segments()` to validate each independently, but that function did not treat `\n` as a segment boundary, while Python's `str.split()` (used to extract each segment's first word) does. A command like `"echo hello\nWrite-Host 'INJECTED'"` produced one segment whose first word was `"echo"` (whitelisted) — the injected second statement was never checked against `allow_prefix`, and PowerShell/cmd/bash all treat a literal newline in a `-Command`/`-c` argument as a statement separator, so it executed. The deny-list check (`re.search` over the whole string) still caught known-bad substrings like `rm -rf` regardless of newlines, which is why the bypass required content *not* already on `deny` (the audit's own PoC used `Write-Host`, not `rm -rf`). **Fix**: `split_command_segments()` in `shell_resolver.py` now splits on `\n` in addition to `| ; & < > \` $(`; `tokenize_command()` treats `\n` as whitespace; `_SHELL_OPERATORS_RE` includes `\n` so multi-line commands correctly route to segment-validated shell execution instead of being mangled into a single corrupted argv token for native exec.
2. **HIGH — `working_dir` escaped with PowerShell syntax regardless of target shell (INJ-02)**: `safe_wd = working_dir.replace('"', '`"')` was applied unconditionally in both `sh_exec_impl` and `sh_script_impl`, before interpolating into `workdir_prefix`. That escape is correct only for `powershell`/`pwsh`; for `cmd` it needed `""` (doubled quote) and for `bash` it needed `\"`. A `working_dir` value containing a literal `"` could break out of the quoted segment on `cmd`/`bash` and inject further shell syntax. **Fix**: new `_escape_workdir(working_dir, shell_name)` in `layer2_shell.py`, used at both call sites, escaping per the actual target shell.
3. **MEDIUM — SSH command validation is local-only (INJ-03)**: `ssh_exec_impl` already validates commands against `is_command_allowed()` before sending them (added in v1.4.5, finding #5) — but that policy runs on the machine hosting `personal-mcp`, not on the remote host the SSH session connects to. A command that passes the local allowlist is still forwarded verbatim and executed with whatever privileges the remote account has, with no equivalent enforcement there. This is an inherent limitation of validating locally before a remote handoff, not a regression of the v1.4.5 fix. Severity assessed as MEDIUM rather than the audit's HIGH: `register_ssh_tools()` doesn't register any SSH tool at all unless `config.ssh.enabled=True` and `~/.ssh/config` exists — SSH is disabled by default and in this deployment, so the gap is currently unreachable. **Fix**: `ssh_exec_impl` now prefixes every result with an explicit `[WARNING]` that local validation does not bind the remote host. Full remote-side enforcement would require deploying a validating wrapper on each remote host — out of scope here (no existing mechanism to deploy anything remotely; flagged as a possible future project, not a local code fix).
4. **MEDIUM — Secret scanner didn't cover journal/notes (INJ-04)**: `scan_text()` was wired into `fs_read_impl` and the shell execution paths (v1.4.2, v1.4.5) but never into `journal_add_impl`/`note_quick_impl` — a credential pasted into a journal entry or quick note was written to disk with zero warning, unlike the same content read from a file or shell output. **Fix**: new `_scan_and_append()` helper in `layer4_personal.py` (same warn-only pattern as `layer2_shell.py`'s `_append_secret_scan`, not shared across layers to avoid a cross-layer dependency for a two-line helper — flagged as minor DRY debt below, not fixed here). `journal_add_impl` signature gained a required `config: AppConfig` parameter to reach the scanner and the `secret_scanning_enabled` flag; its only caller (`register_personal_tools`) was updated accordingly. No test in `test_personal.py` calls `journal_add_impl` directly (it tests `Journal` instead), so this signature change has no test-compatibility impact — verified before making the change.
5. **LOW — Log injection via crafted arguments (INJ-05)**: the audit report pointed at `scrub_sensitive_data()` in `log.py`, but that function only masks dict keys (`password`, `token`, etc.) and was never meant to sanitize control characters in values — and the JSON-encoded audit trail in `server.py`'s `AuditedFastMCP` is already safe, since `json.dumps()` escapes `\n` as the two-character sequence `\n`. The actual vulnerable call sites are `layer2_shell.py`'s two direct `logger.info("sh_exec command=%.200s ...", command, ...)` / `sh_script script=%.100s` calls, which interpolate the raw string via `%s` with no escaping — a command containing a literal newline could forge a fake log line (e.g. a fake `[INFO] User authenticated as admin` entry). **Fix**: new `sanitize_log_value()` in `log.py` (escapes `\n`/`\r` to literal `\n`/`\r`), applied at both call sites in `layer2_shell.py`.

### Notes
- Test coverage checked before each edit, not after: `test_shell_resolver.py` (no existing test exercises `\n` in `tokenize_command`/`has_shell_operators`), `test_shell.py` (`test_sh_exec_argv_with_working_dir` only exercises the native-exec `cwd` kwarg path, never the vulnerable `workdir_prefix` string-interpolation path — unaffected by fix #2), `test_personal.py` (tests `Journal` directly, never `journal_add_impl`), and confirmed no `tests/test_ssh.py` exists at all (SSH layer has zero test coverage, consistent with being disabled by default — flagged, not addressed here).
- Debt flagged, not fixed in this release: `_scan_and_append` in `layer4_personal.py` duplicates the same small pattern as `_append_secret_scan` in `layer2_shell.py` instead of sharing one implementation — left as-is to avoid a cross-layer import for ~6 lines; revisit if a third call site appears.
- `pyproject.toml` version bump still outstanding from 1.4.7 (noted then, not yet applied).

## [1.4.8] — 2026-07-04

### Fixed
- **`project_scan`/`project_find` defaulted to a stale path when called without an explicit `path`**: both `project_scan_impl` and `project_find_impl` used a hardcoded `Path.home() / "Repos"` (i.e. `C:\Users\User\Repos`) as the fallback root. This silently drifted from the live `paths_allow` config once it was narrowed to a single custom directory (`C:\Repos`) — calling either tool without `path` failed with `Path not in allowed directories`, even though the server had a perfectly valid allowed directory configured.
- **Fix**: new helper `_default_project_root(security)` in `layer4_personal.py`, used by both functions instead of the duplicated literal. Returns `paths_allow[0]` (the real source of truth) when available; falls back to `Path.home() / "Repos"` only if `paths_allow` is empty — a misconfigured-server case where no default could be correct anyway, and `resolve_and_validate()` already rejects it with the same clear error as before. No change in behavior for calls that already pass `path` explicitly.

### Notes
- Same operational note as 1.4.6/1.4.7: this fix (and the 1.4.7 `fs_search` fix) will not take effect until the MCP server process is restarted — Python does not hot-reload modules.

## [1.4.7] — 2026-07-04

### Fixed
- **ReDoS risk in `fs_search`**: `fs_search_impl` compiled and ran the user-supplied `pattern` directly against every line of every matched file, with no bound on execution time. A pathological pattern (catastrophic backtracking, e.g. `(a+)+$`) could hang the tool call — and, since `fs_search_impl` ran synchronously inside the async function (no `asyncio.to_thread`, unlike `fs_read_impl`/`fs_write_impl`/etc.), it also blocked the server's entire event loop while running.
- **Fix**: search logic extracted to a plain sync helper (`_fs_search_sync`) and executed via `asyncio.to_thread` wrapped in `asyncio.wait_for(timeout=_SEARCH_TIMEOUT_SECONDS)` (10s constant). A single catastrophic `regex.search()` call cannot be interrupted mid-execution in pure Python (no external timeout-capable regex engine is a dependency of this project, and none was added — YAGNI), so the orphaned thread may keep running in the background, but the MCP call itself now always returns to the caller instead of hanging indefinitely. `re.compile()` is also now wrapped in `try/except re.error`, returning a clean error message for invalid patterns instead of an uncaught exception (same failure class fixed for `fs_delete` in 1.4.6).
- Public tool signature of `fs_search` is unchanged — the timeout is an internal constant, not a new exposed parameter, since there is no evidence yet that per-call configurability is needed.
- 2 new tests: `test_search_invalid_pattern`, `test_search_timeout` (the latter uses `monkeypatch` on `_fs_search_sync`/`_SEARCH_TIMEOUT_SECONDS` rather than a real catastrophic pattern, to keep the test fast and deterministic).

### Notes
- Not addressed in this release (separate, lower-priority findings from the same review pass):
  - `pyproject.toml` version bump to match this changelog.

## [1.4.6] — 2026-07-04

### Fixed
- **`fs_delete` failed with a raw, uncaught exception instead of the expected `permission_required` JSON, even after the ticket was approved**: `fs_delete_impl` called `security.resolve_and_validate(path, "delete")` a second time after the `fs_delete` wrapper had already validated and consumed the grant via `validate_tool_path(path, "delete")`. Because delete tickets are always forced to `SINGLE` (see 1.4.5, finding #3) and `PermissionManager.check_granted()` defaults to `consume=True`, the wrapper's call consumed the only unit of the grant; the second call inside `fs_delete_impl` found no remaining grant and raised `PermissionRequiredError` uncaught, surfacing as `Error executing tool fs_delete: Access to '...' needs delete permission` in the server log instead of the graceful `permission_required` response the wrapper is supposed to produce on denial.
- **Fix**: `fs_delete_impl` now calls `security.resolve_and_validate(path)` without the `operation` argument, matching the existing convention already used by `fs_write_impl`, `fs_move_impl`, and `fs_batch_impl` — the wrapper (`fs_delete()`) is the single point where the `"delete"` operation is checked and the grant consumed; `_impl` functions only use `resolve_and_validate()` for path resolution/existence checks, never to re-check permissions.

### Notes
- No changes to `security.py` or `permissions.py`. The `consume=True` default in `check_granted()` and the "wrapper checks, impl resolves without operation" convention it depends on remain undocumented as an explicit rule — see `AGENTS.md` Gotchas.

## [1.4.5] — 2026-07-03

### Security audit findings and fixes
Full audit covering command injection, script execution, and permission bypass surfaces. Six findings identified and fixed in this release.

1. **CRITICAL — Command whitelist bypass via shell operator chaining**: `is_command_allowed()` previously validated only the first word of the *entire* command string. Any command containing `; | & < > `` or $()` fell back to real shell execution (`powershell -Command "<full string>"`), which interprets every chained segment — none of which were re-validated against the whitelist. Example verified against the live config: `git status; Copy-Item C:\Users\User\.ssh\id_rsa C:\Users\User\Desktop\x.txt` passed the whitelist (first word "git") and executed in full. **Fix**: added `split_command_segments()` (`shell_resolver.py`) to split a command on shell operators outside quotes; `is_command_allowed()` now validates every segment's first word against `allow_prefix`, not just the first one.
2. **CRITICAL — `sh_script` documented as read-only but not enforced**: `AGENTS.md` claimed scripts were "strictly limited to non-modifying actions", but `sh_script_impl` only checked `script[:100]` against the same whitelist as `sh_exec` — no real read-only restriction existed. **Fix**: new `CommandPolicy.readonly_prefix` (separate, stricter list than `allow_prefix`) and `is_script_readonly()`, which validates every non-empty, non-comment line of the script. A single non-matching line rejects the whole script before it touches disk.
3. **HIGH — `fs_delete` "no exceptions" bypassable via wildcard grants**: `fs_request_allow` creates tickets with `operation="*"`; `check_granted()` treated `"*"` as matching any operation, including `"delete"` — silently bypassing the `SINGLE`-only rule added for delete in the previous release. **Fix**: `check_granted()` now explicitly excludes `"delete"` from wildcard (`"*"`) matches, in both session and single grants — delete always requires its own explicit ticket.
4. **MEDIUM — Secret scanning didn't cover shell output**: `scan_text()` was only wired into `fs_read_impl`. A secret printed via `sh_exec("cat .env")` or `git log -p` produced no warning. **Fix**: extracted `format_findings()` as a shared helper (`secretscanner.py`) and wired it into all three result-construction paths in `sh_exec_impl`/`sh_script_impl` (native exec, shell fallback, script execution) — same warn-only behavior as `fs_read`.
5. **MEDIUM — `ssh_exec` had zero command validation**: unlike `sh_exec`, remote commands over SSH (disabled by default) were not checked against `allow_prefix`/`deny`/`require_flag_approval` at all. **Fix**: `ssh_exec_impl` now calls `is_command_allowed()` before executing, same as the local shell path.
6. **Documentation**: `AGENTS.md` rule #2 corrected to accurately describe `sh_script`'s actual (and now real) read-only enforcement.

### Added
- **`fs_delete`** (Layer 1, 18th filesystem tool): deletes a single file. Does not support directories or recursion — returns an explicit error if the target is a directory, by design (YAGNI: no batch/recursive delete until an actual need is identified).
- **`operation="delete"` is isolated from `"write"`**: an existing `write` session grant on a path does **not** grant `delete` on that same path — verified, not just assumed.
- **`delete` tickets are always forced to `SINGLE` grant**, regardless of the level requested via `fs_approve`: `PermissionManager.approve()` downgrades any `session`/`permanent` request to `single` when `ticket.operation == "delete"`, and states this explicitly in the returned message.
- **`security.commands.readonly_prefix`**: new config list (separate from `allow_prefix`) of exact read-only command prefixes (`git status`, `git log`, `ls`, `dir`, `docker ps`, `npm list`, `dotnet --version`, etc.), used exclusively by `sh_script`'s new per-line validation.

### Changed
- **`~/.personal-mcp/config.json` → `security.commands.allow_prefix`**: added `dotnet`, `node`, `pnpm`, `flutter` to support .NET Core, direct Node script execution, pnpm-based projects, and Flutter mobile development. (Applied 2026-07-03; not documented at the time — backfilled here.)

## [1.4.4] — 2026-07-02

### Fixed
- **Audit log never recorded real tool invocations (H1)**: `server.py` assigned `app.call_tool = wrapped_call_tool` *after* `FastMCP.__init__()` had already registered the original `self.call_tool` with the low-level MCP server via a closure captured at decoration time (`FastMCP._setup_handlers()` → `self._mcp_server.call_tool(validate_input=False)(self.call_tool)`). Reassigning the instance attribute afterwards had no effect on that closure, so no real client invocation ever reached the wrapper — `mcp_audit_log` reported 0 operations and `~/.personal-mcp/data/audit.json` was never created despite active shell/filesystem usage. Confirmed by direct inspection of `mcp/server/fastmcp/server.py` (installed package) and by empirical evidence during a diagnostic session (~20 real tool calls, only the tool-internal `mcp_benchmark` entry appeared in the audit log).
- **Fix — `AuditedFastMCP(FastMCP)`**: replaced the monkey-patch with a subclass that overrides `call_tool()` as a real instance method, matching `FastMCP.call_tool(self, name: str, arguments: dict[str, Any])`. `_setup_handlers()` resolves `self.call_tool` via the instance's class (MRO) at the moment it runs inside `super().__init__()`, so the override is picked up correctly for every request — no per-tool changes needed in the 6 layers.
- Removed unused `from functools import wraps` import in `server.py`.

### Notes
- Same investigation also reviewed a burst of ~27 server restarts (2026-07-02 22:43–22:47) and stale entries in `.pytest_cache/lastfailed` referencing tests since renamed/consolidated. Both were downgraded to low severity: file-modification timestamps show an active refactor session in progress at that time, not evidence of a crash-loop or a real regression. No code change was made for either; `pytest tests/ -v` should be re-run to refresh the stale cache when convenient.
- **Verified 2026-07-02**: `pytest tests/ -v` run directly in terminal (outside the MCP tool channel, which had become unresponsive during a prior attempt) — **257/257 passed in 51.49s**. `TestServerHandshake` exercises full server startup through `AuditedFastMCP`, confirming the fix doesn't break the existing contract. The stale-cache concern above is now fully resolved by this clean run.

## [1.4.3] — 2026-07-02

### Changed
- **`fs_request_allow` now creates pending tickets instead of granting directly**: Previously `fs_request_allow` bypassed the ticket system via `grant_direct()`, which contradicted HITL principles. Now it creates a pending ticket through `request_permission()`, requiring explicit `fs_approve` confirmation before access is granted. This makes the pre-authorize flow consistent with the ticket-based approval workflow used by `fs_write` and `fs_edit`.
- **Updated README**: `fs_request_allow` description and HITL section reflect the new pending→approve flow. Test count updated to 257.
- **257 tests** (all pass, up from 255).

## [1.4.2] — 2026-07-02

### Added
- **#4 — Rate limiting per-operation**: Sliding window rate limiter moved from `server.py` into `SecurityValidator._check_rate_limit()`. Applied independently per operation type (read/write) inside `validate_tool_path()`, not globally. Disabled when `rate_limit_commands_per_minute` is 0. 5 new tests.
- **#5 — Secret scanning** (`src/secretscanner.py`): New module with 12 regex patterns for common secrets (GitHub tokens, AWS keys, private keys, JWT, Slack tokens, DB connection strings, etc.). Integrated into `fs_read_impl()` — warns on detection, never blocks. Gated by `SecurityConfig.secret_scanning_enabled` (default: true). 15 new tests.

### Changed
- **Server startup simplified**: Removed `RateLimitError` class, `deque` import, and rate limiting logic from `wrapped_call_tool()` in `server.py`. Rate limiting now lives entirely in `SecurityValidator`.
- **`validate_tool_path()`**: Now calls `_check_rate_limit(operation)` before path validation. Rate limit exceeded returns an error string, consistent with all other validation errors.
- **`SecurityConfig`**: Added `secret_scanning_enabled: bool = True` field.
- **255 tests** (all pass, up from 235).

## [1.4.1] — 2026-07-02

### Changed
- **Relaxed read security model (Option C)**: Read operations in `paths_allow` now pass directly without requiring a grant ticket. Write operations still require explicit grant (session/single/permanent). This restores compatibility with AGENTS.md rule #3 ("No tickets on hot path") for reads while maintaining HITL security for writes.
- **Permanent grants**: `check_granted()` now recognizes paths added via permanent grants for write operations. Reads are auto-allowed by `resolve_and_validate()`.
- **Updated 20 tests** to reflect the new read-vs-write security boundary. Write-only grant tests now verify write behavior instead of read behavior.
- **Permanent grants removed from tool reach**: `fs_approve` and `fs_request_allow` no longer accept `level="permanent"`. Permanent grants must be configured manually in `~/.personal-mcp/config.json`. Single and session grants remain fully functional via tools — defense-in-depth against client-side config failures.

### Fixed
- **KeyError in `check_granted()`**: Resolves operation key before deletion in `_single_grants` consumption path. Single grants with `"read"` key no longer crash when the caller passes a different operation name.

## [1.4.0] — 2026-07-01

### Added
- **Structured Logging System** (`src/log.py`): New logging infrastructure with `RotatingFileHandler`, log levels (INFO, DEBUG, WARN, ERROR), and precise operation timing using `timed()` context manager.
- **Log Inspection Tool** (`mcp_log`): New tool to retrieve and filter server logs directly from the MCP interface.
- **Sensitive Data Sanitization**: Recursive scrubbing of sensitive keys (`password`, `token`, `secret`, etc.) in all server logs to prevent information leakage.
- **Interactive Path Configurator** (`configure_paths.py`): CLI utility to manage `paths_allow` without manual JSON editing.
- **Configuration Template**: `config.demo.json` added as a secure reference for new users.

### Changed
- **Hard-Lock Security Model**: 
  - **Absolute Path Lockdown**: Paths outside `paths_allow` or `data_dir` are now strictly denied immediately. No dynamic tickets can bypass this lock.
  - **Strict Command Whitelist**: Replaced the blocklist model with a mandatory whitelist (`allow_prefix`). Only explicitly approved command prefixes (e.g., `git`, `npm`, `python`) can be executed.
- **Human-in-the-Loop (HITL) Enforcement**: All read, write, and execute operations now require explicit user approval via tickets, regardless of whether the path is in the allowlist. *(Relajado en v1.4.1: reads en `paths_allow` pasan sin ticket)*
- **Recursive Session Grants**: `PermissionManager` now supports recursive session grants; approving a directory allows access to all its sub-paths for the duration of the session.
- **Productivity Pack**: Expanded default command whitelist to include essential dev tools: `uv`, `make`, `docker`, `mkdir`, `rmdir`, `cat`, `type`.

### Fixed
- **Single Grant Consumption Bug**: Fixed a race condition where `SINGLE` grants were consumed during the validation phase before the tool could execute.
- **Path normalization consistency**: Improved path resolution in `PermissionManager` to prevent casing mismatches on Windows.

## [1.3.0] — 2026-07-01
... (rest of the file)

### Added
- **Shell resolver module** (`src/shell_resolver.py`): `ShellInfo` dataclass, `SHELL_REGISTRY` with 4 shells (powershell, pwsh, cmd, bash), `resolve_shell()` with auto-detection. Git Bash discovery via `git --exec-path` or `OPENCODE_GIT_BASH_PATH` env var.
- **Configurable shell**: Respects `ShellConfig.default_shell` (powershell/pwsh/cmd/bash) and `ShellConfig.shell_map` for custom executable paths.
- **Output truncation**: Captured output capped at 1 MiB (`MAX_CAPTURE_BYTES`). Truncated outputs include `[output truncated at 1,048,576 bytes — use a more specific command to narrow results]` notice.
- **Process tree killing**: Timeout cleanup uses `taskkill /pid <pid> /T /F` to recursively terminate process trees on Windows.
- **Advisory path warnings**: Shell commands with absolute paths outside `paths_allow` produce `[warning]` lines in output (non-blocking, informational).
- **12 new tests**: Shell resolver, truncation, cmd/pwsh execution, session rejection for non-interactive shells, kill tree, path warnings.

### Changed
- **`ShellManager`**: Accepts `shell_info: ShellInfo` parameter. Defaults to auto-resolved PowerShell if not provided.
- **`ShellSession`**: Constructor accepts `shell_info` parameter; `start()` uses resolved shell's `session_args` instead of hardcoded `powershell.exe -NoExit -Command -`.
- **`sh_exec_impl`**: Accepts optional `shell_info`; uses resolved shell's `command_args` and `workdir_prefix` for working directory.
- **`sh_script_impl`**: Accepts optional `shell_info`; uses resolved shell's `script_args`; temp file extension adapts to shell (`.ps1`/`.bat`/`.sh`).
- **`sh_session_start_impl`**: Returns error JSON when shell doesn't support interactive sessions (cmd, bash).
- **`register_shell_tools` closures**: `sh_exec`, `sh_script`, `sh_session_send` now produce `[warning]` lines for paths outside allowlist (non-blocking).
- **`ShellConfig`**: Added `shell_map: dict[str, str]` field for custom executable paths.
- **`shell` parameter on tools**: `sh_exec`, `sh_script`, and `sh_session_start` now accept an optional `shell` parameter (e.g. `shell="cmd"`, `shell="pwsh"`). When provided, the tool resolves and uses that shell for that single invocation. Falls back to configured default when omitted.
- **`ShellManager.__init__`**: Now accepts `shell_map` parameter — stored for runtime shell resolution.
- **`ShellManager.resolve_shell(name)`**: New method that delegates to `resolve_shell(name, self.shell_map)`, enabling runtime shell switching.
- **`server.py`**: Passes `config.shell.shell_map` to `ShellManager`.
- **105 tests** (0 skipped): `test_resolve_pwsh` now passes after installing PowerShell 7.5.0 portable. 5 new tests for shell switching.

### Fixed
- Timeout handlers in `sh_exec_impl` and `sh_script_impl` now use `_kill_process_tree()` (taskkill /T /F) instead of `process.kill()`, ensuring child processes are cleaned up.
- `ShellSession.close()` timeout path uses taskkill for recursive cleanup.

## [1.2.0] — 2026-07-01

### Changed
- **Security model from allowlist to blocklist**: `allow_prefix` defaults to `[]` (empty). Any command not in the deny list is allowed. Desktop Commander-compatible model.
- **`authorize()` → `validate_tool_path()`**: Hot-path tools (filesystem, shell) no longer generate permission tickets. Returns a plain error string when a path is outside `paths_allow`. Tickets only appear via explicit `fs_approve`/`fs_deny` tools.
- **`check_granted()` now uses `operation`**: `_session_grants` changed from `Set[str]` to `Dict[str, Set[str]]`. A "read" grant no longer silently authorizes "write".
- **`_validate_command_paths()` uses `is_path_allowed()`**: Shell commands with absolute paths outside the allowlist return a clean error string instead of a ticket JSON blob.
- **Async I/O for all filesystem ops**: `fs_read`, `fs_write`, `fs_diff`, `fs_snapshot` use `asyncio.to_thread()` for blocking file operations. No more event loop blocking.
- **Async I/O for shell scripts**: `sh_script_impl` wraps `write_text()` and `unlink()` in `asyncio.to_thread()`.
- **`fs_write` no longer creates `.bak` backups**: Eliminates unnecessary I/O on every write.
- **`config_path` field on `AppConfig`**: Tests write to isolated temp configs via `config_path`, never touch `~/.personal-mcp/config.json`.

### Fixed
- `PATH_RE` regex now matches forward-slash paths (e.g. `C:/foo/bar`) — PowerShell accepts both separators; backslash-only regex let `C:/` paths bypass shell command scanning.
- `import uvicorn` removed from `server.py` (FastMCP 3.x doesn't use it).
- `SecurityValidator` unreferenced `_resolved_allowed` cache stays valid across config saves.
- Tests no longer pollute real config: `strict_config` fixture includes `config_path`.

### Removed
- `default_deny: bool` from `SecurityConfig` — dead code, never read.

## [1.1.0] — 2026-06-30

### Added
- **Permission system (Layer 6)**: New `PermissionManager` with ticket-based access control. When a tool accesses a path outside the allowlist, a structured `permission_required` response is returned instead of an error, allowing the user to approve via `fs_approve`.
  - Three grant levels: `single` (one-time), `session` (server lifetime), `permanent` (added to config)
  - Automatic expiry of pending tickets after 5 minutes
  - Session grants tracked in-memory; permanent grants persisted to `config.json`
- **6 permission tools**: `fs_approve`, `fs_deny`, `fs_request_allow`, `security_pending`, `security_revoke`, `security_stats`
- **`working_dir` parameter**: `sh_exec` and `sh_script` now accept an optional `working_dir` to scope command execution to a specific directory
- **Absolute path scanning in shell commands**: Commands are scanned for `C:\...` patterns; paths outside the allowlist trigger permission tickets
- **`security.is_path_allowed()`**: Quick boolean check without raising exceptions
- **`security.extract_absolute_paths()`**: Regex-based extraction of Windows absolute paths from text
- **16 permission tests**: Covering ticket lifecycle, grant levels, revoke, stats, direct grants
- **`GrantLevel` enum**: `SINGLE`, `SESSION`, `PERMANENT` with string serialization

### Changed
- **Filesystem layer**: All 11 tools now catch `PathNotAllowedError` and return a permission ticket response instead of failing
- **Shell layer**: `sh_exec` and `sh_script` validate `working_dir` and scan commands for absolute paths
- **`SecurityValidator`**: Optional `perm_manager` attribute wired to `PermissionManager`
- **`PermissionManager.approve()`**: Now accepts optional `level` override parameter
- **`install.ps1`**: Updated tool summary to include Layer 6
- **README.md**: Updated architecture to 6 layers, added Layer 6 tools table, expanded security section

### Fixed
- `PermissionManager.revoke_ticket()` had a `token` / `ticket` typo — corrected
- `SecurityValidator.extract_absolute_paths()` regex now stops at whitespace (was greedy across words like "and")
- `PermissionManager._session_grants` now stores resolved paths (normalizes Windows casing) to fix set lookup mismatches

## [1.0.0] — 2026-06-30

### Added
- Initial release with 5-layer architecture
- Layer 1: Filesystem — 11 tools for read/write/edit/list/tree/search/find/info/diff/batch/snapshot
- Layer 2: Shell — 9 tools with persistent PowerShell sessions
- Layer 3: SSH — 4 tools (disabled by default)
- Layer 4: Personal — 8 tools (journal, notes, project scanning)
- Layer 5: Health — 8 diagnostic tools
- Security validator with path allowlist/denylist and command policy
- Audit log with circular buffer (10k entries) and JSON persistence
- 57 initial tests
- Installer script for Claude Desktop integration
- Verification script for live testing
