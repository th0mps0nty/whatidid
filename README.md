# whatidid

> **"What did I actually build this week?"**

Cross-agent AI work digest that reads sessions from **every local AI tool you run** — Hermes, OpenAI Codex CLI, Claude Code, GitHub Copilot CLI, Continue, and more — and translates them into a business-readable value report.

Inspired by the [What-I-Did-Copilot](https://github.com/microsoft/What-I-Did-Copilot) project. Built to work across all agents, not just one.

---

## What it does

- Reads session data from: Hermes Agent (SQLite), OpenAI Codex CLI, Claude Code, GitHub Copilot CLI, Continue
- Groups related work by project and workstream
- Estimates human-equivalent hours using effort heuristics
- Calculates value delivered (hours × blended hourly rate)
- Estimates AI credit cost and shows value multiple (e.g. 1300×)
- Outputs: Markdown report, JSON data, and a self-contained HTML report (Linear.app-inspired design)
- Redacts credentials, tokens, and sensitive paths automatically

## Quick start

```bash
pip install whatidid
whatidid --days 7
# → ~/whatidid-reports/AI_WORK_DIGEST_LATEST.html
```

## CLI options

```
whatidid [OPTIONS]

  --days INT           Look-back window in days (default: 7)
  --max-sessions INT   Cap on sessions to process (default: 100)
  --hourly-rate FLOAT  Blended hourly rate for value calc (default: 125.0)
  --no-html            Skip HTML output
  --output-dir PATH    Where to write reports (default: ~/whatidid-reports)
```

## Supported sources

| Source | Location | Notes |
|--------|----------|-------|
| Hermes Agent | `~/.hermes/sessions.db` | SQLite, full metadata |
| OpenAI Codex CLI | `~/.codex/` | JSONL session files |
| Claude Code | `~/.claude/projects/` | JSONL conversation files |
| GitHub Copilot CLI | `~/.config/github-copilot/` | Chat history |
| Continue | `~/.continue/` | Session JSON files |

## Sample output

```
Sessions : 93
Projects : 9
Est. hours: 169.25
Value     : $21,156
AI cost   : $16.05
Multiple  : 1318×
Confidence: medium (0.72)
```

Reports saved to `~/whatidid-reports/`.

## License

MIT — Tyler Thompson
