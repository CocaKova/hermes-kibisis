# Changelog

## 0.1.2 — 2026-09-02

* Remember more of the files a fetch writes: `wget -O`, bundled short flags (`-qO`, `-sSLo`), `--output-document`, `| tee`, and the URL basename that `curl -O` / bare `wget` drop in the working directory. Stdout forms (`-O-`, `-o -`) and `/dev/null` are never recorded.
* Claude Code hook: the `Read` branch now honours the fetched-path memory. Each hook call is a fresh process, so that memory is persisted to `$XDG_STATE_HOME/kibisis/fetched_paths.json` (override with `KIBISIS_STATE_DIR`). Before this the feature was dead in the hook.

## 0.1.1 — 2026-09-02

* Defer to core's `untrusted_source(name, args)` when present (hermes-agent #101597) so a core that frames the side doors itself never gets a second envelope from kibisis; the scan footer still rides along.

## 0.1.0 — 2026-09-02

* First release. Envelopes `read_file` on the web cache (and on files a fetching command wrote), `terminal` remote fetches (`curl`, `wget`, `gh api/issue/pr`, any URL), and `execute_code` that touches the network.
* Runs Hermes' shared threat-pattern scan over side-door content and over core-wrapped web/browser/MCP results; leaves a visible `[kibisis]` footer when it fires. Blocks nothing.
* JSON tool results stay JSON: the envelope goes around the content field, and an `_kibisis` key records source and scan verdict.
* Claude Code companion hook (`claude-code/kibisis_hook.py`): warn-only `PostToolUse` note for WebFetch/WebSearch/Bash fetches/Reads of fetched files.
