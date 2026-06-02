#!/usr/bin/env python3
"""Cross-tool AI/agent session inventory and impact digest.

Local-first, read-only collector inspired by microsoft/What-I-Did-Copilot, but
broadened for Tyler's AI/agent estate: Hermes, Copilot CLI, Claude Code, Codex,
Continue, VS Code/Cursor Copilot Chat when present, and future adapters.

Design constraints:
- Never reads .env, credential stores, auth token files, browser profiles, cookies,
  keychains, private keys, or password stores.
- Redacts secret-looking strings from snippets.
- Defaults to metadata/summarized context, not raw transcript export.
- Emits deterministic JSON + Markdown reports under HermesOps/knowledge/reports.
"""
from __future__ import annotations

import argparse
import ast
import dataclasses
import datetime as dt
import glob
import hashlib
import html
import json
import math
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

HOME = Path.home()
REPORT_DIR = Path(os.environ["WHATIDID_REPORT_DIR"]) if "WHATIDID_REPORT_DIR" in os.environ else Path.home() / "whatidid-reports"

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|bearer)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]

DANGEROUS_NAME_PAT = re.compile(
    r"(?i)(\.env|envrc|id_rsa|id_ed25519|private[_-]?key|keychain|cookies?|password|passwd|secret|token|auth|oauth|credentials?|credential|\.npmrc|webduder)"
)

APPROVALS = {
    "yes", "y", "ok", "okay", "sure", "continue", "proceed", "do it",
    "approved", "looks good", "sounds good", "ship it", "go ahead"
}

LOGIC_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".cs",
    ".cpp", ".c", ".h", ".hpp", ".sh", ".bash", ".zsh", ".ps1", ".rb",
    ".php", ".r", ".sql", ".kt", ".swift", ".dart", ".scala", ".ex", ".exs",
    ".vue", ".svelte", ".tf", ".hcl",
}


def redact(text: Any, limit: int = 500) -> str:
    s = "" if text is None else str(text)
    for pat in SECRET_PATTERNS:
        s = pat.sub("[REDACTED_SECRET]", s)
    s = re.sub(r"[A-Za-z0-9+/]{80,}={0,2}", "[REDACTED_LONG_TOKEN]", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > limit:
        return s[:limit-1] + "…"
    return s


def safe_path(path: Path | str) -> bool:
    return not DANGEROUS_NAME_PAT.search(str(path))


def safe_text(text: Any) -> bool:
    """False when a snippet points at credential/secrets surfaces."""
    return not DANGEROUS_NAME_PAT.search(str(text))


def display_path(path: Any, limit: int = 240) -> str:
    """Return a report-safe, home-relative path string."""
    s = redact(path, limit)
    home = str(HOME)
    if s.startswith(home):
        s = "~" + s[len(home):]
    return s


def clean_path_fragment(path: Any) -> str:
    """Extract one clean path from noisy transcript text.

    AI session stores often contain terminal output fragments, Markdown fences,
    and newlines after a path. Keep only a plausible first path segment so the
    report remains readable and does not accidentally include command output.
    """
    s = str(path).strip().strip("`'\"[](),")
    s = s.split("\\n", 1)[0].split("\n", 1)[0].split("\\t", 1)[0]
    s = re.split(r"(?:\s--\s|\sstdout\b|\sstderr\b|\s◆|\s✓|\s📄)", s, maxsplit=1)[0]
    s = s.rstrip("`'\"[](),:;")
    return s


def safe_display_path(path: Any, limit: int = 180) -> str:
    cleaned = clean_path_fragment(path)
    home = str(HOME)
    if (
        not cleaned
        or cleaned in {"/Users/...", "~/...", "~"}
        or "CHANGE_ME" in cleaned
        or "…" in cleaned
        or any(ch in cleaned for ch in "[]^{}")
        or (cleaned.startswith("/Users/") and not cleaned.startswith(home + "/"))
        or not safe_path(cleaned)
    ):
        return ""
    return display_path(cleaned, limit)


def project_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


PROJECT_ALIASES = {
    "access": "access-assured",
    "assured": "access-assured",
    "access-assured": "access-assured",
    "accessassured": "access-assured",
    "access-assured-site": "access-assured",
    "astro-site": "access-assured",
    "agents-status-update-feature": "access-assured",
    "draftly": "draftly",
    "-draftly": "draftly",
    "pocket-shift": "pocket-shift",
    "pocket-shift-app": "pocket-shift",
    "pocket-shift-mobile": "pocket-shift",
    "pocket-shift-flutter": "pocket-shift",
    "pocket_shift": "pocket-shift",
    "hermesops": "HermesOps",
    "hermes-ops": "HermesOps",
    "systems": "Tetrad Systems",
    "tetrad-systems": "Tetrad Systems",
}


def load_project_catalog() -> list[dict[str, str]]:
    """Load project/repo paths from the HermesOps knowledge vault."""
    rows: list[dict[str, str]] = []
    index_dir = HOME / "HermesOps" / "knowledge" / "index"
    for name in ("git_repos.jsonl", "projects.jsonl"):
        p = index_dir / name
        if not p.exists():
            continue
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    path = obj.get("path")
                    proj = obj.get("name") or (Path(path).name if path else "")
                    if path and proj and safe_path(path):
                        rows.append({"path": str(path), "project": str(proj)})
        except Exception:
            continue
    # Longest paths first so nested worktrees/subrepos resolve before parents.
    return sorted(rows, key=lambda r: len(r["path"]), reverse=True)


def normalize_project_name(project: str, project_path: str = "", catalog: list[dict[str, str]] | None = None, context: str = "") -> str:
    project_only = project_slug(project)
    path_blob = project_path.replace("~", str(HOME), 1)
    path_slug = project_slug(project_path)

    # Trust explicit project names and indexed working directories before fuzzy
    # transcript context. Otherwise a HermesOps session that mentions Access
    # Assured can be incorrectly reclassified as Access Assured.
    if project_only in PROJECT_ALIASES:
        return PROJECT_ALIASES[project_only]
    if project_only in {"hermesops", "hermes-ops"}:
        return "HermesOps"
    if catalog and path_blob:
        for row in catalog:
            if path_blob.startswith(row["path"]):
                return PROJECT_ALIASES.get(project_slug(row["project"]), row["project"])
    if any(x in path_slug for x in ["access-assured", "accessassured", "access-assured-site"]):
        return "access-assured"
    if "draftly" in path_slug:
        return "draftly"
    if "pocket-shift" in path_slug or "pocket_shift" in project_path.lower():
        return "pocket-shift"
    if "hermesops" in path_slug or "hermes-ops" in path_slug:
        return "HermesOps"
    if "tetrad" in path_slug:
        return "Tetrad Systems"

    ambiguous = project_only in {"", "unknown", "new-project", "downloads", "tylerthompson"} or project.startswith("[REDACTED")
    blob = " ".join(x for x in [project, project_path, context] if x)
    slug = project_slug(blob)
    if ambiguous:
        if any(x in slug for x in ["access-assured", "accessassured", "access-assured-site"]):
            return "access-assured"
        if "/access/assured" in blob.lower() or " access assured" in blob.lower():
            return "access-assured"
        if "draftly" in slug:
            return "draftly"
        if "pocket-shift" in slug or "pocket_shift" in blob.lower():
            return "pocket-shift"
        if "hermesops" in slug or "hermes-ops" in slug:
            return "HermesOps"
        if "tetrad" in slug:
            return "Tetrad Systems"
    return redact(project or (Path(project_path).name if project_path else "unknown"), 80)


def apply_project_normalization(sessions: list[Session]) -> dict[str, int]:
    catalog = load_project_catalog()
    changed: Counter[str] = Counter()
    for s in sessions:
        before = s.project or Path(s.project_path).name or "unknown"
        context = " ".join([s.first_prompt, " ".join(s.files_touched[:20]), s.repository])
        normalized = normalize_project_name(before, s.project_path, catalog, context=context)
        if normalized != before:
            changed[f"{before} -> {normalized}"] += 1
        s.project = normalized
        if s.project_path:
            s.project_path = display_path(s.project_path)
        if s.raw_path:
            s.raw_path = display_path(s.raw_path)
    return dict(changed)


def parse_time(value: Any) -> dt.datetime | None:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            # Hermes uses seconds, JS logs often use ms.
            if value > 10_000_000_000:
                value = value / 1000
            return dt.datetime.fromtimestamp(value, tz=dt.timezone.utc)
        s = str(value).replace("Z", "+00:00")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
        return dt.datetime.fromisoformat(s if re.search(r"[+-]\d{2}:?\d{2}$", s) else s + "+00:00")
    except Exception:
        return None


def iso(d: dt.datetime | None) -> str:
    return d.astimezone().isoformat(timespec="seconds") if d else ""


def day_of(d: dt.datetime | None) -> str:
    return d.astimezone().date().isoformat() if d else "unknown"


def should_include(ts: dt.datetime | None, start: dt.datetime | None, end: dt.datetime | None) -> bool:
    if ts is None:
        return True
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True


def walk_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    if not safe_path(path):
        return
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        yield obj
                except Exception:
                    continue
    except Exception:
        return


def hash_id(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:16]


@dataclasses.dataclass
class Session:
    source: str
    session_id: str
    started_at: str = ""
    ended_at: str = ""
    project_path: str = ""
    project: str = ""
    repository: str = ""
    branch: str = ""
    model: str = ""
    title: str = ""
    user_turns: int = 0
    assistant_turns: int = 0
    tool_calls: int = 0
    files_touched: list[str] = dataclasses.field(default_factory=list)
    commands: list[str] = dataclasses.field(default_factory=list)
    first_prompt: str = ""
    intents: list[str] = dataclasses.field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    raw_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def substantive(text: str) -> bool:
    cleaned = re.sub(r"\s+", " ", text.strip().lower()).strip(".! ")
    return bool(cleaned) and not (len(cleaned.split()) <= 5 and cleaned in APPROVALS)


def classify_intents(texts: list[str], tools: Counter[str]) -> list[str]:
    blob = "\n".join(texts).lower()
    out = []
    if any(w in blob for w in ["research", "find", "look up", "investigate", "analyze", "analyse"]): out.append("research/analysis")
    if any(w in blob for w in ["build", "implement", "create", "add", "ship", "feature"]): out.append("build/implementation")
    if any(w in blob for w in ["fix", "bug", "error", "debug", "traceback", "failing"]): out.append("debug/fix")
    if any(w in blob for w in ["test", "verify", "smoke", "lint", "build"]): out.append("verification")
    if any(w in blob for w in ["deploy", "publish", "release", "merge", "pr ", "pull request"]): out.append("delivery")
    if tools.get("read") or tools.get("view") or tools.get("search_files") or tools.get("grep"):
        out.append("context-gathering")
    if tools.get("write") or tools.get("edit") or tools.get("patch") or tools.get("create"):
        out.append("artifact-editing")
    return sorted(set(out)) or ["general-ai-work"]


def estimate_hours(s: Session) -> float:
    turns_h = max(0, -0.15 + 0.67 * math.log(s.user_turns + 1)) if s.user_turns else 0
    tools_h = 0.07 * math.log2(s.tool_calls + 1) if s.tool_calls else 0
    files_h = 0.10 * math.log2(len(s.files_touched) + 1) if s.files_touched else 0
    tokens_h = 0.03 * math.log2((s.output_tokens / 1000) + 1) if s.output_tokens else 0
    total = max(0.25 if s.user_turns else 0, turns_h + tools_h + files_h + tokens_h)
    if len(s.files_touched) >= 10:
        total *= 1.25
    elif len(s.files_touched) >= 5:
        total *= 1.10
    return round(total * 4) / 4


def harvest_hermes(start, end) -> list[Session]:
    db = HOME / ".hermes" / "state.db"
    if not db.exists(): return []
    out = []
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("select * from sessions order by started_at desc").fetchall()
    except Exception:
        return []
    for r in rows:
        st = parse_time(r["started_at"])
        en = parse_time(r["ended_at"] if "ended_at" in r.keys() else None)
        if not should_include(st, start, end): continue
        sid = r["id"]
        s = Session(source="hermes", session_id=sid, started_at=iso(st), ended_at=iso(en),
                    model=redact(r["model"] if "model" in r.keys() else "", 120),
                    user_turns=int(r["message_count"] or 0), tool_calls=int(r["tool_call_count"] or 0),
                    input_tokens=int(r["input_tokens"] or 0), output_tokens=int(r["output_tokens"] or 0),
                    cache_read_tokens=int(r["cache_read_tokens"] or 0), cache_write_tokens=int(r["cache_write_tokens"] or 0),
                    raw_path=str(db))
        msgs = con.execute("select role, content, tool_name, tool_calls, timestamp from messages where session_id=? order by id limit 500", (sid,)).fetchall()
        prompts=[]; tools=Counter(); files=set(); commands=[]
        assistant=0; users=0
        for m in msgs:
            role=m["role"]
            content=m["content"] or ""
            if role == "user" and substantive(content):
                users += 1; prompts.append(content)
                if not s.first_prompt: s.first_prompt = redact(content, 240)
            elif role == "assistant":
                assistant += 1
            tn=m["tool_name"]
            if tn: tools[tn]+=1
            for p in re.findall(r"(?:/Users/[^\s'\"\)]+|~/[^\s'\"\)]+)", content):
                safe_p = safe_display_path(p)
                if safe_p: files.add(safe_p)
            # Hermes stores terminal outputs in message content; do not print
            # those as commands because outputs can include sensitive paths.
        s.user_turns = users or s.user_turns
        s.assistant_turns = assistant
        s.files_touched = sorted(files)[:50]
        s.commands = commands[:20]
        s.intents = classify_intents(prompts, tools)
        out.append(s)
    return out


def harvest_copilot(start, end) -> list[Session]:
    base = HOME / ".copilot" / "session-state"
    out=[]
    if not base.is_dir(): return out
    for events in base.glob("*/events.jsonl"):
        sid = events.parent.name
        workspace = events.parent / "workspace.yaml"
        s = Session(source="github-copilot-cli", session_id=sid, raw_path=str(events))
        prompts=[]; tools=Counter(); files=set(); models=Counter(); starts=[]; ends=[]
        context={}
        for e in walk_jsonl(events):
            ts=parse_time(e.get("timestamp"));
            if not should_include(ts,start,end): continue
            starts.append(ts); ends.append(ts)
            t=e.get("type",""); d=e.get("data") or {}
            if t=="session.start":
                context=d.get("context") or {}; s.model=redact(d.get("selectedModel") or "",80)
            elif t=="user.message":
                text=redact(re.sub(r"<[^>]+>.*?</[^>]+>", "", str(d.get("content") or ""), flags=re.S), 500)
                if substantive(text):
                    prompts.append(text); s.user_turns+=1
                    if not s.first_prompt: s.first_prompt=redact(text,240)
            elif t=="assistant.message":
                s.assistant_turns+=1; models[redact(d.get("model") or "",80)] += 1
                s.output_tokens += int(d.get("outputTokens") or 0)
                for tr in d.get("toolRequests") or []:
                    name=tr.get("name") or "tool"; tools[name]+=1; s.tool_calls += 1
                    inp=tr.get("input") or {}
                    p=inp.get("path") if isinstance(inp,dict) else ""
                    safe_p = safe_display_path(p)
                    if safe_p: files.add(safe_p)
            elif t=="tool.execution_start":
                name=d.get("toolName") or d.get("mcpToolName") or "tool"; tools[name]+=1
                args=d.get("arguments") or {}
                if isinstance(args,dict):
                    p=args.get("path") or args.get("file_path")
                    safe_p = safe_display_path(p)
                    if safe_p: files.add(safe_p)
                    cmd=args.get("command")
                    if cmd and safe_text(cmd): s.commands.append(redact(cmd,160))
            elif t=="session.shutdown":
                s.input_tokens += sum(((md.get("usage") or {}).get("inputTokens") or 0) for md in (d.get("modelMetrics") or {}).values())
                if not s.output_tokens:
                    s.output_tokens += sum(((md.get("usage") or {}).get("outputTokens") or 0) for md in (d.get("modelMetrics") or {}).values())
                cc=d.get("codeChanges") or {}
                for p in cc.get("filesModified") or []:
                    safe_p = safe_display_path(p)
                    if safe_p: files.add(safe_p)
        s.started_at=iso(min([x for x in starts if x], default=None)); s.ended_at=iso(max([x for x in ends if x], default=None))
        s.project_path=redact(context.get("cwd") or "", 240); s.repository=redact(context.get("repository") or "", 240); s.branch=redact(context.get("branch") or "",80)
        s.project=Path(s.project_path).name if s.project_path else sid[:12]
        if not s.model and models: s.model=models.most_common(1)[0][0]
        s.files_touched=sorted(files)[:50]; s.commands=s.commands[:20]; s.intents=classify_intents(prompts,tools)
        if s.user_turns or s.tool_calls: out.append(s)
    return out


def decode_claude_project_path(folder: Path) -> str:
    name = folder.name
    if name.startswith("-"):
        return "/" + name[1:].replace("-", "/")
    return name.replace("-", "/")


def harvest_claude(start, end) -> list[Session]:
    out=[]
    for f in (HOME/".claude"/"projects").glob("**/*.jsonl"):
        if not safe_path(f): continue
        s=Session(source="claude-code", session_id=f.stem, project_path=redact(decode_claude_project_path(f.parent),240), raw_path=str(f))
        s.project=Path(s.project_path).name if s.project_path else f.parent.name
        prompts=[]; tools=Counter(); files=set(); starts=[]; ends=[]
        for e in walk_jsonl(f):
            ts=parse_time(e.get("timestamp"));
            if not should_include(ts,start,end): continue
            starts.append(ts); ends.append(ts)
            typ=e.get("type") or ""; op=e.get("operation") or ""
            content=e.get("content") or e.get("message") or e.get("text") or ""
            blob = json.dumps(e, ensure_ascii=False) if not isinstance(content,str) or not content else str(content)
            if typ in ("user", "human") or op in ("user", "prompt"):
                if substantive(blob):
                    s.user_turns+=1; prompts.append(blob)
                    if not s.first_prompt: s.first_prompt=redact(blob,240)
            elif typ in ("assistant", "completion"):
                s.assistant_turns+=1
            for name in re.findall(r"\b(Bash|Read|Write|Edit|MultiEdit|Grep|Glob|Task|WebFetch|TodoWrite)\b", blob):
                tools[name.lower()]+=1
            for p in re.findall(r"(?:/Users/[^\s'\"\)]+|~/[^\s'\"\)]+)", blob):
                safe_p = safe_display_path(p)
                if safe_p: files.add(safe_p)
            for cmd in re.findall(r"(?:command|cmd)[:=]\s*['\"]([^'\"]{1,200})", blob):
                if safe_text(cmd): s.commands.append(redact(cmd,160))
        s.started_at=iso(min([x for x in starts if x], default=None)); s.ended_at=iso(max([x for x in ends if x], default=None))
        s.tool_calls=sum(tools.values()); s.files_touched=sorted(files)[:50]; s.commands=s.commands[:20]; s.intents=classify_intents(prompts,tools)
        if s.user_turns or s.assistant_turns or s.tool_calls: out.append(s)
    return out


def harvest_codex(start, end) -> list[Session]:
    out=[]
    for f in (HOME/".codex"/"sessions").glob("**/*.jsonl"):
        if not safe_path(f): continue
        s=Session(source="openai-codex", session_id=f.stem, raw_path=str(f))
        prompts=[]; tools=Counter(); files=set(); starts=[]; ends=[]
        for e in walk_jsonl(f):
            ts=parse_time(e.get("timestamp") or (e.get("payload") or {}).get("timestamp"))
            if not should_include(ts,start,end): continue
            starts.append(ts); ends.append(ts)
            typ=e.get("type") or ""; p=e.get("payload") or {}
            if typ in ("session_meta", "session_config"):
                s.project_path=redact(p.get("cwd") or "",240); s.model=redact(p.get("model") or p.get("model_provider") or "",100)
                git=p.get("git") or {}; s.branch=redact(git.get("branch") or "",80); s.repository=redact(git.get("repository_url") or "",240)
            blob=json.dumps(p, ensure_ascii=False)
            if typ in ("user_message", "user_input") or p.get("role")=="user":
                text=p.get("text") or p.get("content") or blob
                if substantive(str(text)):
                    s.user_turns += 1; prompts.append(str(text))
                    if not s.first_prompt: s.first_prompt=redact(text,240)
            elif typ in ("assistant_message", "agent_message") or p.get("role")=="assistant":
                s.assistant_turns += 1
            if typ in ("function_call", "tool_call", "exec_command") or "tool" in typ:
                name=p.get("name") or p.get("tool_name") or typ; tools[name]+=1; s.tool_calls+=1
            for pth in re.findall(r"(?:/Users/[^\s'\"\)]+|~/[^\s'\"\)]+)", blob):
                safe_p = safe_display_path(pth)
                if safe_p: files.add(safe_p)
            cmd=p.get("command") if isinstance(p,dict) else None
            if cmd and safe_text(cmd): s.commands.append(redact(cmd,160))
        s.started_at=iso(min([x for x in starts if x], default=None)); s.ended_at=iso(max([x for x in ends if x], default=None))
        s.project=Path(s.project_path).name if s.project_path else "unknown"
        s.files_touched=sorted(files)[:50]; s.commands=s.commands[:20]; s.intents=classify_intents(prompts,tools)
        if s.user_turns or s.assistant_turns or s.tool_calls: out.append(s)
    return out


def harvest_continue(start, end) -> list[Session]:
    out=[]
    base=HOME/".continue"/"sessions"
    if not base.is_dir(): return out
    for f in base.glob("*.json"):
        if not safe_path(f): continue
        try: data=json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except Exception: continue
        items=data if isinstance(data,list) else data.get("history") or data.get("sessions") or data.get("messages") or []
        s=Session(source="continue", session_id=f.stem, raw_path=str(f), project="unknown")
        prompts=[]; tools=Counter(); starts=[]; ends=[]
        if isinstance(items, dict): items=list(items.values())
        for it in items if isinstance(items,list) else []:
            if not isinstance(it,dict): continue
            ts=parse_time(it.get("timestamp") or it.get("createdAt") or it.get("date"))
            if not should_include(ts,start,end): continue
            if ts: starts.append(ts); ends.append(ts)
            role=it.get("role") or it.get("message",{}).get("role") if isinstance(it.get("message"),dict) else ""
            content=it.get("content") or it.get("text") or json.dumps(it,ensure_ascii=False)
            if role=="user" and substantive(str(content)):
                s.user_turns+=1; prompts.append(str(content));
                if not s.first_prompt: s.first_prompt=redact(content,240)
            elif role=="assistant": s.assistant_turns+=1
        s.started_at=iso(min(starts, default=None)); s.ended_at=iso(max(ends, default=None)); s.intents=classify_intents(prompts,tools)
        if s.user_turns or s.assistant_turns: out.append(s)
    return out


def harvest_all(start, end) -> list[Session]:
    sessions=[]
    for fn in [harvest_hermes, harvest_copilot, harvest_claude, harvest_codex, harvest_continue]:
        try: sessions.extend(fn(start,end))
        except Exception as e: print(f"WARN {fn.__name__}: {e}", file=sys.stderr)
    return sessions


def inventory_sources() -> list[dict[str,Any]]:
    specs=[
        ("Hermes Agent SQLite", HOME/".hermes"/"state.db"),
        ("Hermes session JSONL", HOME/".hermes"/"sessions"),
        ("GitHub Copilot CLI", HOME/".copilot"/"session-state"),
        ("VS Code Copilot Chat", HOME/"Library/Application Support/Code/User/globalStorage/emptyWindowChatSessions"),
        ("Claude Code projects", HOME/".claude"/"projects"),
        ("Claude Code sessions", HOME/".claude"/"sessions"),
        ("Claude telemetry", HOME/".claude"/"telemetry"),
        ("OpenAI Codex sessions", HOME/".codex"/"sessions"),
        ("Continue sessions", HOME/".continue"/"sessions"),
        ("Cursor globalStorage", HOME/"Library/Application Support/Cursor/User/globalStorage"),
        ("OpenCode", HOME/".opencode"),
        ("Aider chat history", HOME/".aider.chat.history.md"),
    ]
    rows=[]
    for name,path in specs:
        exists=path.exists()
        files=0
        if exists and path.is_dir():
            for _,_,fs in os.walk(path):
                files += len([x for x in fs if safe_path(x)])
                if files > 20000: break
        elif exists: files=1
        rows.append({"name":name,"path":display_path(path),"exists":exists,"files":files,"mtime":iso(parse_time(path.stat().st_mtime)) if exists else ""})
    return rows


BLENDED_HOURLY_RATE = 125.0  # $/hr — blended AI engineering/operator replacement value, configurable via --hourly-rate
DEFAULT_MODEL_PRICING_PER_MILLION = {
    "input": 3.00,
    "output": 15.00,
    "cache_read": 0.30,
    "cache_write": 3.75,
}


def money(v: float) -> str:
    return f"${v:,.0f}" if abs(v) >= 100 else f"${v:,.2f}"


def safe_label(v: Any, limit: int = 120) -> str:
    return html.escape(redact(str(v or ""), limit))


def safe_command_display(command: Any, limit: int = 160) -> str:
    text = redact(str(command or ""), limit)
    text = re.sub(r"/Users/[^\s'\"]+", "~/<path>", text)
    text = re.sub(r"~/(?:\.hermes|\.codex|\.claude|\.config|Developer|Documents|Downloads)[^\s'\"]+", "~/<path>", text)
    if not safe_text(text):
        return ""
    return text


def summarize_prompt(text: str, limit: int = 220) -> str:
    """Return a safe, human-readable prompt summary instead of raw JSON/env wrappers."""
    raw = redact(str(text or ""), 4000)
    extracted = ""
    for parser in (json.loads, ast.literal_eval):
        try:
            obj = parser(raw)
        except Exception:
            continue
        try:
            if isinstance(obj, dict):
                msg = obj.get("message")
                if isinstance(msg, dict):
                    extracted = str(msg.get("content") or "")
                elif obj.get("content"):
                    extracted = str(obj.get("content") or "")
                elif obj.get("text"):
                    extracted = str(obj.get("text") or "")
            elif isinstance(obj, list) and obj:
                first = obj[0]
                if isinstance(first, dict):
                    extracted = str(first.get("text") or first.get("content") or "")
            if extracted:
                raw = extracted
                break
        except Exception:
            pass
    raw = raw.replace("\\n", "\n").replace('\\"', '"')
    if not extracted:
        m = re.search(r'"content"\s*:\s*"(.{1,800}?)"\s*[,}]', raw, flags=re.S)
        if not m and '"content"' in raw:
            m = re.search(r'"content"\s*:\s*"(.{1,800})', raw, flags=re.S)
        if not m:
            m = re.search(r"'text'\s*:\s*['\"](.{1,800}?)['\"]", raw, flags=re.S)
        if not m and "'text'" in raw:
            m = re.search(r"'text'\s*:\s*['\"](.{1,800})", raw, flags=re.S)
        if not m:
            m = re.search(r'"text"\s*:\s*"(.{1,800}?)"', raw, flags=re.S)
        if m:
            raw = m.group(1).replace("\\n", "\n").replace('\\"', '"')
    raw = re.sub(r"<environment_context>.*?</environment_context>", " ", raw, flags=re.I | re.S)
    raw = re.sub(r"<INSTRUCTIONS>.*?</INSTRUCTIONS>", " ", raw, flags=re.I | re.S)
    raw = re.sub(r"# AGENTS\.md instructions.*", " ", raw, flags=re.I | re.S)
    raw = re.sub(r'/Users/[^\s\'"<>),]+', "~/<path>", raw)
    raw = re.sub(r'~/[^\s\'"<>),]+', "~/<path>", raw)
    raw = re.sub(r"[{}\[\]_:,]{2,}", " ", raw)
    raw = re.sub(r"\s+", " ", raw).strip(" -'\"")
    if any(marker in raw for marker in ("parentUuid", "input_text", "environment_context", "approval_policy", "sandbox_mode")):
        return "Session activity summarized from local agent metadata."
    if not raw or len(raw.split()) < 2:
        return "Session activity summarized from local agent metadata."
    return redact(raw, limit)


def token_market_cost(sessions: list[Session]) -> float:
    return sum(
        (s.input_tokens * DEFAULT_MODEL_PRICING_PER_MILLION["input"]
         + s.output_tokens * DEFAULT_MODEL_PRICING_PER_MILLION["output"]
         + s.cache_read_tokens * DEFAULT_MODEL_PRICING_PER_MILLION["cache_read"]
         + s.cache_write_tokens * DEFAULT_MODEL_PRICING_PER_MILLION["cache_write"])
        / 1_000_000
        for s in sessions
    )


def confidence_for_session(s: Session) -> str:
    score = 0
    if s.user_turns: score += 1
    if s.tool_calls: score += 1
    if s.input_tokens or s.output_tokens: score += 1
    if s.files_touched: score += 1
    if s.started_at: score += 1
    return "high" if score >= 4 else "medium" if score >= 2 else "low"


def estimate_confidence(sessions: list[Session]) -> dict[str, Any]:
    counts = Counter(confidence_for_session(s) for s in sessions)
    n = max(1, len(sessions))
    weighted = (counts.get("high", 0) * 1.0 + counts.get("medium", 0) * 0.65 + counts.get("low", 0) * 0.35) / n
    label = "high" if weighted >= 0.78 else "medium" if weighted >= 0.50 else "low"
    return {"label": label, "score": round(weighted, 2), "counts": dict(counts)}


def workstream_title(project: str, intents: Iterable[str]) -> str:
    primary = next(iter(intents), "general-ai-work")
    labels = {
        "build/implementation": "Implementation and product build-out",
        "debug/fix": "Debugging and repair work",
        "verification": "Verification, testing, and release confidence",
        "research/analysis": "Research, analysis, and planning",
        "delivery": "Delivery, deployment, and publishing",
        "artifact-editing": "Artifact and document production",
        "context-gathering": "Context gathering and codebase orientation",
        "general-ai-work": "General AI-assisted work",
    }
    return f"{project}: {labels.get(primary, primary)}"


def category_for_file(path: str) -> str:
    name = Path(path).name.lower()
    ext = Path(name).suffix
    if ext in {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".cs", ".sh"}:
        return "Code & scripts"
    if ext in {".md", ".txt", ".docx", ".pdf"}:
        return "Docs & reports"
    if ext in {".json", ".yaml", ".yml", ".toml", ".csv"}:
        return "Data & config"
    if ext in {".html", ".css", ".svg"}:
        return "HTML/UI artifacts"
    return "Other artifacts"


def group_work_items(sessions: list[Session], hourly_rate: float) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[Session]] = defaultdict(list)
    for s in sessions:
        project = s.project or "unknown"
        primary = s.intents[0] if s.intents else "general-ai-work"
        groups[(project, primary)].append(s)
    items = []
    for (project, primary), ss in groups.items():
        hours = sum(estimate_hours(x) for x in ss)
        intents = Counter(i for s in ss for i in s.intents).most_common(5)
        files = []
        for s in ss:
            for f in s.files_touched:
                if safe_text(f) and f not in files:
                    files.append(f)
        first_prompts = [s.first_prompt for s in ss if s.first_prompt]
        items.append({
            "project": project,
            "primary_intent": primary,
            "title": workstream_title(project, [primary]),
            "session_count": len(ss),
            "sources": sorted(set(s.source for s in ss)),
            "estimated_hours": round(hours, 2),
            "estimated_value": round(hours * hourly_rate, 2),
            "tool_calls": sum(s.tool_calls for s in ss),
            "user_turns": sum(s.user_turns for s in ss),
            "assistant_turns": sum(s.assistant_turns for s in ss),
            "input_tokens": sum(s.input_tokens for s in ss),
            "output_tokens": sum(s.output_tokens for s in ss),
            "intents": [i for i, _ in intents],
            "artifact_count": len(files),
            "artifact_categories": dict(Counter(category_for_file(f) for f in files)),
            "example_prompts": [summarize_prompt(x, 180) for x in first_prompts[:3]],
            "confidence": estimate_confidence(ss)["label"],
            "date_range": {
                "from": min((s.started_at for s in ss if s.started_at), default=""),
                "to": max((s.started_at for s in ss if s.started_at), default=""),
            },
        })
    return sorted(items, key=lambda x: (-x["estimated_value"], x["project"], x["primary_intent"]))


def deliverables_summary(sessions: list[Session]) -> dict[str, Any]:
    by_cat = Counter()
    examples = defaultdict(list)
    for s in sessions:
        for f in s.files_touched:
            if not safe_text(f):
                continue
            cat = category_for_file(f)
            by_cat[cat] += 1
            if len(examples[cat]) < 10:
                examples[cat].append(f)
    return {"counts": dict(by_cat), "examples": {k: v for k, v in examples.items()}}


def activity_summary(sessions: list[Session]) -> dict[str, Any]:
    by_day = Counter()
    by_hour = Counter()
    for s in sessions:
        st = parse_time(s.started_at)
        if not st:
            continue
        by_day[st.date().isoformat()] += 1
        by_hour[st.hour] += 1
    buckets = {
        "Early morning": sum(v for h, v in by_hour.items() if 5 <= h < 9),
        "Morning": sum(v for h, v in by_hour.items() if 9 <= h < 12),
        "Afternoon": sum(v for h, v in by_hour.items() if 12 <= h < 17),
        "Evening": sum(v for h, v in by_hour.items() if 17 <= h < 21),
        "Night": sum(v for h, v in by_hour.items() if h >= 21 or h < 5),
    }
    return {"busiest_days": by_day.most_common(10), "time_buckets": buckets}


def build_impact_payload(sessions: list[Session], hourly_rate: float) -> dict[str, Any]:
    total_hours = round(sum(estimate_hours(s) for s in sessions), 2)
    token_cost = token_market_cost(sessions)
    value = total_hours * hourly_rate
    workstreams = group_work_items(sessions, hourly_rate)
    project_values = defaultdict(lambda: {"hours": 0.0, "value": 0.0, "sessions": 0})
    for s in sessions:
        project = s.project or "unknown"
        h = estimate_hours(s)
        project_values[project]["hours"] += h
        project_values[project]["value"] += h * hourly_rate
        project_values[project]["sessions"] += 1
    return {
        "hourly_rate": hourly_rate,
        "estimated_human_hours": total_hours,
        "estimated_value_delivered": round(value, 2),
        "estimated_ai_market_cost": round(token_cost, 4),
        "estimated_ai_credits": int(round(token_cost / 0.01)) if token_cost > 0 else 0,
        "value_to_ai_market_cost_ratio": round(value / token_cost, 1) if token_cost > 0 else None,
        "confidence": estimate_confidence(sessions),
        "workstreams": workstreams,
        "deliverables": deliverables_summary(sessions),
        "activity": activity_summary(sessions),
        "project_values": {
            k: {"hours": round(v["hours"], 2), "value": round(v["value"], 2), "sessions": v["sessions"]}
            for k, v in sorted(project_values.items(), key=lambda kv: (-kv[1]["value"], kv[0]))
        },
        "methodology": {
            "value_formula": "estimated_human_hours × hourly_rate",
            "hourly_rate_note": "Blended AI engineering/operator replacement value; configurable with --hourly-rate.",
            "ai_cost_formula": "tokens × default per-million model rates; lower bound when tool stores sparse token metadata.",
            "grouping": "canonical_project + primary_intent, similar to upstream goal merging by project/repo with work-family rollups.",
            "caveat": "Directional value estimate, not an invoice, tax claim, or guaranteed savings figure.",
        },
    }


def render_html_report(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    impact = payload["impact"]
    generated = safe_label(payload.get("generated_at"))
    value = money(impact["estimated_value_delivered"])
    ai_cost = money(impact["estimated_ai_market_cost"])
    ratio = impact.get("value_to_ai_market_cost_ratio")
    ratio_txt = f"{ratio:,.0f}×" if ratio else "—"
    conf = impact["confidence"]
    hour_rate = impact["hourly_rate"]
    human_hours = impact["estimated_human_hours"]

    def metric(label, val, sub=""):
        sub_html = f'<div class="metric-sub">{safe_label(sub)}</div>' if sub else ''
        return f'<div class="metric"><div class="metric-value">{safe_label(val)}</div><div class="metric-label">{safe_label(label)}</div>{sub_html}</div>'

    source_cards = "".join(
        f'<span class="pill">{safe_label(k)} <b>{v}</b></span>'
        for k, v in sorted(summary["source_counts"].items(), key=lambda kv: (-kv[1], kv[0]))
    )
    project_rows = "".join(
        f'<tr><td>{safe_label(k)}</td><td>{v["sessions"]}</td><td>{v["hours"]:.2f}h</td><td>{money(v["value"])}</td></tr>'
        for k, v in list(impact["project_values"].items())[:12]
    )
    workstream_cards = "".join(
        f'<article class="workstream"><div class="workstream-top"><span class="tag">{safe_label(w["primary_intent"])}</span><span class="confidence {safe_label(w["confidence"])}">{safe_label(w["confidence"])}</span></div><h3>{safe_label(w["title"])}</h3><div class="work-meta">{w["session_count"]} sessions · {", ".join(safe_label(x) for x in w["sources"])} · {w["tool_calls"]} tool calls</div><div class="work-numbers"><b>{w["estimated_hours"]:.2f}h</b><b>{money(w["estimated_value"])}</b><b>{w["artifact_count"]} artifacts</b></div><p>{safe_label((w.get("example_prompts") or [""])[0], 240)}</p></article>'
        for w in impact["workstreams"][:24]
    )
    deliverable_rows = "".join(
        f'<tr><td>{safe_label(cat)}</td><td>{count}</td><td>{safe_label(", ".join(impact["deliverables"]["examples"].get(cat, [])[:4]), 280)}</td></tr>'
        for cat, count in sorted(impact["deliverables"].get("counts", {}).items(), key=lambda kv: (-kv[1], kv[0]))
    )
    max_bucket = max(impact["activity"]["time_buckets"].values() or [1])
    activity_bars = "".join(
        f'<div class="bar-row"><span>{safe_label(k)}</span><div class="bar"><i style="width:{min(100, v / max(1, max_bucket) * 100):.0f}%"></i></div><b>{v}</b></div>'
        for k, v in impact["activity"].get("time_buckets", {}).items()
    )
    method = impact["methodology"]

    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Work Digest — Value Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{{--bg:#08090a;--panel:#0f1011;--surface:#191a1b;--text:#f7f8f8;--muted:#8a8f98;--sub:#d0d6e0;--accent:#7170ff;--green:#10b981;--border:rgba(255,255,255,.08)}}
*{{box-sizing:border-box}} body{{margin:0;background:radial-gradient(circle at 20% 0%,rgba(113,112,255,.22),transparent 32%),var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;font-feature-settings:'cv01','ss03';line-height:1.5}} .wrap{{max-width:1180px;margin:0 auto;padding:34px 20px 80px}} .hero{{padding:46px 0 28px;border-bottom:1px solid var(--border)}} .eyebrow{{color:var(--accent);font-size:12px;text-transform:uppercase;letter-spacing:1.4px;font-weight:600}} h1{{font-size:clamp(38px,6vw,72px);line-height:1;letter-spacing:-1.4px;margin:14px 0;font-weight:510}} .lede{{font-size:18px;color:var(--sub);max-width:780px}} .grid{{display:grid;gap:14px}} .metrics{{grid-template-columns:repeat(4,minmax(0,1fr));margin:24px 0}} .metric,.card,.workstream{{background:rgba(255,255,255,.035);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}} .metric-value{{font-size:30px;color:var(--text);font-weight:590;letter-spacing:-.7px}} .metric-label{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.9px;font-weight:600}} .metric-sub{{font-size:12px;color:var(--muted);margin-top:4px}}
.value-banner{{margin:28px 0;background:linear-gradient(135deg,#047857,#10b981);border:1px solid rgba(255,255,255,.14);border-radius:18px;overflow:hidden}} .value-inner{{display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:1px;background:rgba(255,255,255,.18)}} .value-cell{{background:rgba(0,0,0,.08);padding:22px;text-align:center}} .value-cell strong{{display:block;font-size:38px;letter-spacing:-1px}} .value-cell span{{font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:rgba(255,255,255,.72);font-weight:700}}
h2{{font-size:26px;letter-spacing:-.5px;margin:34px 0 14px}} .two{{grid-template-columns:1.1fr .9fr}} .pills{{display:flex;flex-wrap:wrap;gap:8px}} .pill,.tag,.confidence{{display:inline-flex;gap:6px;align-items:center;border:1px solid var(--border);border-radius:999px;padding:5px 10px;background:rgba(255,255,255,.04);color:var(--sub);font-size:12px}} .tag{{color:#c7d2fe}} .confidence.high{{color:#86efac}} .confidence.medium{{color:#fde68a}} .confidence.low{{color:#fca5a5}}
table{{width:100%;border-collapse:collapse;font-size:13px}} th,td{{padding:10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}} th{{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.8px}} .work-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}} .workstream h3{{margin:10px 0 6px;font-size:18px}} .work-meta,.workstream p{{color:var(--muted);font-size:13px}} .work-numbers{{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}} .work-numbers b{{font-size:13px;background:rgba(113,112,255,.14);border:1px solid rgba(113,112,255,.25);border-radius:8px;padding:6px 8px}} .workstream-top{{display:flex;justify-content:space-between;gap:10px}}
.bar-row{{display:grid;grid-template-columns:120px 1fr 40px;gap:10px;align-items:center;margin:9px 0;color:var(--sub);font-size:13px}} .bar{{height:10px;background:rgba(255,255,255,.06);border-radius:999px;overflow:hidden}} .bar i{{display:block;height:100%;background:linear-gradient(90deg,var(--accent),#10b981)}} .note{{color:var(--muted);font-size:12px}} .footer{{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);padding-top:18px}}
@media(max-width:760px){{.metrics,.two,.work-grid,.value-inner{{grid-template-columns:1fr}}}}
</style></head><body><main class="wrap">
<section class="hero"><div class="eyebrow">Cross-agent What-I-Did report · generated {generated}</div><h1>AI work translated into business value.</h1><p class="lede">Local-first digest across Hermes, Codex, Claude Code, Copilot CLI, Continue, and detected agent stores. It groups similar work, estimates human-equivalent effort, surfaces value delivered, and keeps raw transcripts/secrets out of the report.</p></section>
<section class="grid metrics">
{metric('Value delivered', value, f'{human_hours:.2f}h × ${hour_rate:.0f}/hr')}
{metric('AI investment', ai_cost, f"~{impact['estimated_ai_credits']} credits from token metadata")}
{metric('Value multiple', ratio_txt, 'directional value / AI market cost')}
{metric('Confidence', conf['label'], f"score {conf['score']} · {conf['counts']}")}
</section>
<section class="value-banner"><div class="value-inner"><div class="value-cell"><span>Value Delivered</span><strong>{value}</strong><small>{human_hours:.2f} human-equivalent hours</small></div><div class="value-cell"><span>Sessions</span><strong>{summary['session_count']}</strong><small>{summary['project_count']} projects</small></div><div class="value-cell"><span>Tool Calls</span><strong>{summary['tool_calls']}</strong><small>{summary['user_turns']} user turns</small></div></div></section>
<section class="grid two"><div class="card"><h2>Source coverage</h2><div class="pills">{source_cards}</div></div><div class="card"><h2>Work pattern</h2>{activity_bars}</div></section>
<section><h2>Grouped workstreams</h2><div class="grid work-grid">{workstream_cards}</div></section>
<section class="grid two"><div class="card"><h2>Project value rollup</h2><table><thead><tr><th>Project</th><th>Sessions</th><th>Hours</th><th>Value</th></tr></thead><tbody>{project_rows}</tbody></table></div><div class="card"><h2>What got produced</h2><table><thead><tr><th>Category</th><th>Refs</th><th>Examples</th></tr></thead><tbody>{deliverable_rows}</tbody></table></div></section>
<section class="card"><h2>Methodology and caveats</h2><p><b>Value formula:</b> {safe_label(method['value_formula'])}. <b>Grouping:</b> {safe_label(method['grouping'])}</p><p><b>AI cost:</b> {safe_label(method['ai_cost_formula'])}</p><p class="note">{safe_label(method['caveat'])} Reports are local-first, redacted, and omit raw transcripts by default. Estimates are intentionally directional, similar in spirit to upstream What-I-Did Copilot's effort/value presentation.</p></section>
<div class="footer">Generated by HermesOps cross-agent digest. Markdown and JSON companions are in the same reports directory.</div>
</main></body></html>'''


def write_reports(sessions: list[Session], args) -> tuple[Path,Path,Path]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp=dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path=REPORT_DIR/f"ai-work-digest-{stamp}.json"
    md_path=REPORT_DIR/f"ai-work-digest-{stamp}.md"
    html_path=REPORT_DIR/f"ai-work-digest-{stamp}.html"
    normalization_changes = apply_project_normalization(sessions)
    by_source=Counter(s.source for s in sessions)
    by_project=defaultdict(list)
    for s in sessions:
        by_project[s.project or Path(s.project_path).name or "unknown"].append(s)
    impact = build_impact_payload(sessions, float(args.hourly_rate))
    payload={
        "generated_at": iso(dt.datetime.now(dt.timezone.utc)),
        "range": {"from": args.from_date or "", "to": args.to_date or "", "days": args.days},
        "sources": inventory_sources(),
        "summary": {
            "session_count": len(sessions),
            "source_counts": dict(by_source),
            "project_count": len(by_project),
            "estimated_human_hours": sum(estimate_hours(s) for s in sessions),
            "tool_calls": sum(s.tool_calls for s in sessions),
            "user_turns": sum(s.user_turns for s in sessions),
            "assistant_turns": sum(s.assistant_turns for s in sessions),
            "input_tokens": sum(s.input_tokens for s in sessions),
            "output_tokens": sum(s.output_tokens for s in sessions),
        },
        "impact": impact,
        "normalization_changes": normalization_changes,
        "sessions": [s.to_dict() | {"estimated_hours": estimate_hours(s)} for s in sessions],
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines=[]
    lines.append("# AI Work Digest — Cross-tool Session Report")
    lines.append("")
    lines.append(f"Generated: {payload['generated_at']}")
    lines.append(f"Range: {payload['range']}")
    lines.append("")
    lines.append("## Executive summary")
    lines.append(f"- Sessions found: {len(sessions)}")
    lines.append(f"- Projects represented: {len(by_project)}")
    lines.append(f"- Estimated human-equivalent effort: {payload['summary']['estimated_human_hours']:.2f} hours")
    lines.append(f"- User turns / assistant turns / tool calls: {payload['summary']['user_turns']} / {payload['summary']['assistant_turns']} / {payload['summary']['tool_calls']}")
    lines.append(f"- Token totals where available: input {payload['summary']['input_tokens']:,}, output {payload['summary']['output_tokens']:,}")
    lines.append("")
    lines.append("## Value delivered and AI investment")
    lines.append(f"- Estimated value delivered: {money(impact['estimated_value_delivered'])} ({impact['estimated_human_hours']:.2f}h × ${impact['hourly_rate']:.0f}/hr)")
    lines.append(f"- Estimated AI market cost: {money(impact['estimated_ai_market_cost'])} (~{impact['estimated_ai_credits']} credits from token metadata)")
    if impact.get('value_to_ai_market_cost_ratio'):
        lines.append(f"- Directional value multiple: {impact['value_to_ai_market_cost_ratio']:,.1f}× value delivered / AI market cost")
    lines.append(f"- Estimate confidence: {impact['confidence']['label']} (score {impact['confidence']['score']}, counts {impact['confidence']['counts']})")
    lines.append("- Caveat: directional value estimate, not an invoice, tax claim, or guaranteed savings figure.")
    lines.append("")
    lines.append("## Grouped workstreams")
    lines.append("| Workstream | Sessions | Sources | Est. hours | Est. value | Artifacts | Confidence |")
    lines.append("|---|---:|---|---:|---:|---:|---|")
    for w in impact['workstreams'][:20]:
        lines.append(f"| {redact(w['title'],120)} | {w['session_count']} | {', '.join(w['sources'])} | {w['estimated_hours']:.2f} | {money(w['estimated_value'])} | {w['artifact_count']} | {w['confidence']} |")
    lines.append("")
    lines.append("## Source inventory")
    lines.append("| Source | Present | Files | Path | Last modified |")
    lines.append("|---|---:|---:|---|---|")
    for src in payload["sources"]:
        lines.append(f"| {src['name']} | {'yes' if src['exists'] else 'no'} | {src['files']} | `{src['path']}` | {src['mtime']} |")
    lines.append("")
    lines.append("## Source coverage")
    for k,v in by_source.most_common(): lines.append(f"- {k}: {v} sessions")
    lines.append("")
    if normalization_changes:
        lines.append("## Project normalization applied")
        lines.append("These aliases were collapsed before project rollup, using HermesOps project indexes plus safe built-in aliases.")
        for k,v in sorted(normalization_changes.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
            lines.append(f"- {redact(k, 120)}: {v} sessions")
        lines.append("")
    lines.append("## Project rollup")
    lines.append("| Project | Sessions | Sources | Est. hours | Tool calls | Top intents |")
    lines.append("|---|---:|---|---:|---:|---|")
    for proj, ss in sorted(by_project.items(), key=lambda kv: (-sum(estimate_hours(x) for x in kv[1]), kv[0])):
        intents=Counter(i for s in ss for i in s.intents).most_common(4)
        sources=", ".join(sorted(set(s.source for s in ss)))
        lines.append(f"| {redact(proj,80)} | {len(ss)} | {sources} | {sum(estimate_hours(s) for s in ss):.2f} | {sum(s.tool_calls for s in ss)} | {', '.join(i for i,_ in intents)} |")
    lines.append("")
    lines.append("## Session details")
    for s in sorted(sessions, key=lambda x: x.started_at or "", reverse=True)[:args.max_sessions]:
        lines.append(f"### {s.source}: {redact(s.project or 'unknown',80)} — {s.started_at or 'unknown time'}")
        lines.append(f"- Session ID: `{redact(s.session_id,120)}`")
        if s.project_path:
            safe_project_path = safe_display_path(s.project_path)
            if safe_project_path: lines.append(f"- Project path: `{safe_project_path}`")
        if s.repository: lines.append(f"- Repository: `{s.repository}`")
        if s.branch: lines.append(f"- Branch: `{s.branch}`")
        if s.model: lines.append(f"- Model/provider: {s.model}")
        lines.append(f"- Metrics: {s.user_turns} user turns, {s.assistant_turns} assistant turns, {s.tool_calls} tool calls, est. {estimate_hours(s):.2f} human-equivalent hours")
        if s.intents: lines.append(f"- Intents: {', '.join(s.intents)}")
        if s.first_prompt: lines.append(f"- First prompt: {summarize_prompt(s.first_prompt, 220)}")
        safe_files = [safe_display_path(p) for p in s.files_touched if safe_display_path(p)]
        if safe_files: lines.append(f"- Files/context referenced: {', '.join('`'+p+'`' for p in safe_files[:8])}")
        safe_cmds = [safe_command_display(c) for c in s.commands if safe_command_display(c)]
        if safe_cmds: lines.append(f"- Commands observed: {', '.join('`'+c+'`' for c in safe_cmds[:5])}")
        safe_raw_path = safe_display_path(s.raw_path)
        if safe_raw_path: lines.append(f"- Raw source: `{safe_raw_path}`")
        lines.append("")
    lines.append("## Privacy and limitations")
    lines.append("- This report intentionally summarizes and redacts; it does not dump raw transcripts or secrets.")
    lines.append("- Human-equivalent hours are deterministic directional estimates, not billing or savings claims.")
    lines.append("- Adapters use local session schemas observed on this machine; new tools can be added by implementing another harvest_* adapter.")
    lines.append("- Some tools store sparse metadata only, so token/project/file counts may be lower bounds.")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    html_path.write_text(render_html_report(payload), encoding="utf-8")
    latest_md=REPORT_DIR/"AI_WORK_DIGEST_LATEST.md"
    latest_json=REPORT_DIR/"AI_WORK_DIGEST_LATEST.json"
    latest_html=REPORT_DIR/"AI_WORK_DIGEST_LATEST.html"
    latest_md.write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")
    latest_json.write_text(json_path.read_text(encoding="utf-8"), encoding="utf-8")
    latest_html.write_text(html_path.read_text(encoding="utf-8"), encoding="utf-8")
    return md_path,json_path,html_path


def main(argv=None):
    ap=argparse.ArgumentParser(description="Cross-tool AI/agent session digest")
    ap.add_argument("--days", type=int, default=7, help="Lookback window when --from/--to not provided")
    ap.add_argument("--from", dest="from_date", help="Start date YYYY-MM-DD")
    ap.add_argument("--to", dest="to_date", help="End date YYYY-MM-DD inclusive")
    ap.add_argument("--max-sessions", type=int, default=120)
    ap.add_argument("--hourly-rate", type=float, default=BLENDED_HOURLY_RATE, help="Blended human-equivalent value rate used for value-delivered estimates")
    args=ap.parse_args(argv)
    now=dt.datetime.now(dt.timezone.utc)
    if args.from_date:
        start=parse_time(args.from_date)
    else:
        start=now - dt.timedelta(days=args.days)
    if args.to_date:
        end=parse_time(args.to_date)
        if end: end=end + dt.timedelta(days=1) - dt.timedelta(seconds=1)
    else:
        end=now
    sessions=harvest_all(start,end)
    md,jsonp,htmlp=write_reports(sessions,args)
    print(f"sessions={len(sessions)}")
    print(f"markdown={md}")
    print(f"json={jsonp}")
    print(f"html={htmlp}")

if __name__ == "__main__":
    main()
