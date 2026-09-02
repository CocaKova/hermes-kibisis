# Changelog

## 0.1.0 — 2026-09-02

* First release. Envelopes `read_file` on the web cache (and on files a fetching command wrote), `terminal` remote fetches (`curl`, `wget`, `gh api/issue/pr`, any URL), and `execute_code` that touches the network.
* Runs Hermes' shared threat-pattern scan over side-door content and over core-wrapped web/browser/MCP results; leaves a visible `[kibisis]` footer when it fires. Blocks nothing.
* JSON tool results stay JSON: the envelope goes around the content field, and an `_kibisis` key records source and scan verdict.
* Claude Code companion hook (`claude-code/kibisis_hook.py`): warn-only `PostToolUse` note for WebFetch/WebSearch/Bash fetches/Reads of fetched files.
