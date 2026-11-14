#!/usr/bin/env python3
"""dockerscope - a fast, zero-dependency static linter for Dockerfiles.

    python dockerscope.py [PATH ...]

It never builds or runs anything: it only reads your Dockerfiles.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

__version__ = "1.0.0"

# rule id -> (default severity, title, hint)
RULES: Dict[str, Tuple[str, str, str]] = {
    "DS000": ("error", "Syntax problem", "Fix the instruction; every Dockerfile needs a FROM first."),
    "DS001": ("warning", "Base image is untagged or uses :latest",
              "Pin an exact version (ideally a digest), e.g. python:3.12-slim."),
    "DS002": ("warning", "Container runs as root",
              "Add a non-root user: RUN useradd -m app  then  USER app"),
    "DS003": ("warning", "apt-get install without --no-install-recommends",
              "Add --no-install-recommends to keep the image small."),
    "DS004": ("error", "apt-get install without -y",
              "Add -y so the build never waits for a prompt."),
    "DS005": ("warning", "apt lists are not cleaned up",
              "Chain 'rm -rf /var/lib/apt/lists/*' in the same RUN."),
    "DS006": ("warning", "apt-get update in its own RUN layer",
              "Combine 'apt-get update && apt-get install ...' in one RUN to avoid stale caches."),
    "DS007": ("warning", "cd used inside RUN", "Use WORKDIR instead of 'cd' inside RUN."),
    "DS008": ("info", "ADD used where COPY is enough",
              "Use COPY; ADD is only needed for remote URLs or tar auto-extraction."),
    "DS009": ("warning", "WORKDIR is not absolute", "Use an absolute path such as WORKDIR /app."),
    "DS010": ("warning", "pip install without --no-cache-dir",
              "Use pip install --no-cache-dir to avoid storing wheels in the layer."),
    "DS011": ("warning", "Remote script piped into a shell",
              "Download, verify a checksum, then execute - never pipe straight into sh."),
    "DS012": ("warning", "Multiple CMD/ENTRYPOINT in one stage",
              "Only the last one takes effect; remove the others."),
    "DS013": ("error", "Possible secret baked into ENV/ARG",
              "Pass secrets at runtime or use BuildKit secrets (RUN --mount=type=secret)."),
    "DS014": ("warning", "SSH port 22 exposed",
              "Do not run SSH in containers; use docker exec or your orchestrator."),
    "DS015": ("info", "No HEALTHCHECK in final stage",
              "Add a HEALTHCHECK so orchestrators can detect a hung container."),
    "DS016": ("warning", "sudo used during build",
              "Builds already run as root; drop sudo (and switch user with USER)."),
    "DS017": ("info", "Shell-form CMD/ENTRYPOINT",
              'Use exec form, e.g. CMD ["python", "app.py"], so signals reach your process.'),
    "DS018": ("info", "MAINTAINER is deprecated",
              'Use LABEL org.opencontainers.image.authors="you" instead.'),
    "DS019": ("warning", "apk add without --no-cache",
              "Use apk add --no-cache to avoid a separate cache cleanup."),
    "DS020": ("warning", "chmod 777 makes files world-writable",
              "Grant only the permissions needed, e.g. chmod 755 or 644."),
}

SEV_RANK = {"info": 0, "warning": 1, "error": 2}
KNOWN = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV", "ADD", "COPY", "ENTRYPOINT",
    "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}
SECRET_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)", re.I)
IGNORE_RE = re.compile(r"#\s*dockerscope-ignore:\s*([A-Za-z0-9_, ]+)")

APT_INSTALL = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b")
APT_UPDATE = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*update\b")
PIP_INSTALL = re.compile(r"\bpip[0-9.]*\s+(?:-\S+\s+)*install\b")
APK_ADD = re.compile(r"\bapk\s+(?:-\S+\s+)*add\b")
YES_FLAG = re.compile(r"(?:^|\s)(?:-[a-zA-Z]*y[a-zA-Z]*|--yes|--assume-yes|-qq)(?:\s|$)")
CURL_PIPE = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b")
CD_RE = re.compile(r"(?:^|&&|;|\|\|)\s*cd\s+\S")
SUDO_RE = re.compile(r"(?:^|\s|&&|;|\|)sudo\s")
CHMOD_RE = re.compile(r"\bchmod\b[^;&|]*\b(?:0?777|a\+rwx)\b")
ARCHIVE_RE = re.compile(r"\.(?:tar|tgz|tbz2?|txz|tar\.gz|tar\.bz2|tar\.xz|tar\.zst)$", re.I)
URL_RE = re.compile(r"^(?:https?|ftp)://|^git@")
HEREDOC_RE = re.compile(r"<<-?\s*[\"']?(\w+)[\"']?")


@dataclass
class Instruction:
    line: int
    name: str
    args: str


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    message: str
    hint: str
    file: str = ""


def parse(text: str) -> List[Instruction]:
    """Turn Dockerfile text into instructions (handles continuations and heredocs)."""
    lines = text.splitlines()
    out: List[Instruction] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        buf: List[str] = []
        cur = lines[i]
        while True:
            s = cur.rstrip()
            if s.endswith("\\"):
                buf.append(s[:-1])
                i += 1
                while i < len(lines) and (not lines[i].strip() or lines[i].strip().startswith("#")):
                    i += 1
                if i >= len(lines):
                    break
                cur = lines[i]
            else:
                buf.append(s)
                i += 1
                break
        joined = " ".join(p.strip() for p in buf).strip()
        parts = joined.split(None, 1)
        if not parts:
            continue
        name = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""
        for delim in HEREDOC_RE.findall(args):
            end = next((j for j in range(i, len(lines)) if lines[j].strip() == delim), None)
            if end is None:
                continue
            body = [l.strip() for l in lines[i:end] if l.strip()]
            args += " ; " + " ; ".join(body)
            i = end + 1
        out.append(Instruction(start, name, args))
    return out


def collect_ignores(text: str) -> Dict[int, Set[str]]:
    """'# dockerscope-ignore: DS001, DS002' silences rules on the next instruction."""
    ignores: Dict[int, Set[str]] = {}
    pending: Set[str] = set()
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        m = IGNORE_RE.match(s)
        if m:
            pending |= {r.strip().upper() for r in m.group(1).split(",") if r.strip()}
            continue
        if not s or s.startswith("#"):
            continue
        if pending:
            ignores[n] = pending
            pending = set()
    return ignores


def split_args(args: str) -> List[str]:
    args = args.strip()
    if args.startswith("["):
        try:
            data = json.loads(args)
            if isinstance(data, list):
                return [str(x) for x in data]
        except ValueError:
            pass
    return [t for t in args.split() if not t.startswith("--")]


def env_pairs(args: str) -> List[Tuple[str, str]]:
    if re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*=", args):
        pat = r"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|\S*)"
        return [(m.group(1), m.group(2).strip("\"'")) for m in re.finditer(pat, args)]
    parts = args.split(None, 1)
    if not parts:
        return []
    return [(parts[0], parts[1].strip("\"'") if len(parts) > 1 else "")]


def is_secret(name: str) -> bool:
    return bool(SECRET_RE.search(name)) and not name.upper().endswith("_FILE")


def parse_from(args: str) -> Tuple[str, Optional[str]]:
    toks = [t for t in args.split() if not t.startswith("--")]
    image = toks[0] if toks else ""
    alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else None
    return image, alias


def lint(text: str, filename: str = "Dockerfile") -> List[Finding]:
    instrs = parse(text)
    ignores = collect_ignores(text)
    out: List[Finding] = []

    def add(rule: str, line: int, message: str, sev: Optional[str] = None) -> None:
        if rule in ignores.get(line, ()):
            return
        default_sev, _title, hint = RULES[rule]
        out.append(Finding(rule, sev or default_sev, line, message, hint, filename))

    if not instrs:
        add("DS000", 1, "Dockerfile has no instructions")
        return out
    if instrs[0].name not in ("FROM", "ARG"):
        add("DS000", instrs[0].line, "Dockerfile must start with FROM (ARG may come first)")

    aliases: Set[str] = set()
    stages: List[dict] = []
    stage: Optional[dict] = None

    for ins in instrs:
        n, a = ins.name, ins.args.strip()
        if n not in KNOWN:
            add("DS000", ins.line, f"Unknown instruction '{ins.name}'")
            continue
        if n == "ONBUILD":
            continue
        if n == "ARG":
            name = (a.split("=", 1)[0].split() or [""])[0]
            if is_secret(name):
                add("DS013", ins.line,
                    f"ARG '{name}' looks like a secret and is visible via 'docker history'", "warning")
        if n == "FROM":
            image, alias = parse_from(a)
            name_part = image.rsplit("/", 1)[-1]
            skip = (not image or image.lower() == "scratch" or "$" in image
                    or image.lower() in aliases or "@" in image)
            if not skip:
                if ":" not in name_part:
                    add("DS001", ins.line, f"Base image '{image}' has no tag (implicitly :latest)")
                elif name_part.split(":", 1)[1].lower() == "latest":
                    add("DS001", ins.line, f"Base image '{image}' uses the moving :latest tag")
            stage = {"from": ins, "image": image, "cmd": [], "entry": [], "user": None, "health": False}
            stages.append(stage)
            if alias:
                aliases.add(alias.lower())
            continue
        if stage is None:
            if n != "ARG":
                add("DS000", ins.line, f"{n} appears before the first FROM")
            continue

        if n == "RUN":
            cmd = a
            cached = "type=cache" in cmd
            if APT_INSTALL.search(cmd):
                if "--no-install-recommends" not in cmd:
                    add("DS003", ins.line, "apt-get install is missing --no-install-recommends")
                if not YES_FLAG.search(cmd):
                    add("DS004", ins.line, "apt-get install is missing -y and may hang the build")
                if "/var/lib/apt/lists" not in cmd and not cached:
                    add("DS005", ins.line, "apt package lists are left in the layer")
            elif APT_UPDATE.search(cmd):
                add("DS006", ins.line, "apt-get update runs alone, so its layer can go stale")
            if PIP_INSTALL.search(cmd) and "--no-cache-dir" not in cmd and not cached:
                add("DS010", ins.line, "pip install is missing --no-cache-dir")
            if APK_ADD.search(cmd) and "--no-cache" not in cmd and "/var/cache/apk" not in cmd:
                add("DS019", ins.line, "apk add is missing --no-cache")
            if CD_RE.search(cmd):
                add("DS007", ins.line, "RUN changes directory with cd")
            if CURL_PIPE.search(cmd):
                add("DS011", ins.line, "A downloaded script is piped straight into a shell")
            if SUDO_RE.search(cmd):
                add("DS016", ins.line, "sudo is used inside the build")
            if CHMOD_RE.search(cmd):
                add("DS020", ins.line, "chmod 777 (or a+rwx) makes files world-writable")
        elif n == "ADD":
            toks = split_args(a)
            srcs = toks[:-1]
            if srcs and not any("$" in s or URL_RE.match(s) or ARCHIVE_RE.search(s) for s in srcs):
                add("DS008", ins.line, "ADD is used for plain local files")
        elif n == "WORKDIR":
            if a and not (a.startswith("/") or a.startswith("$") or re.match(r"^[A-Za-z]:[\\/]", a)):
                add("DS009", ins.line, f"WORKDIR '{a}' is a relative path")
        elif n == "ENV":
            for name, val in env_pairs(a):
                if is_secret(name) and val and not val.startswith("$"):
                    add("DS013", ins.line, f"ENV '{name}' bakes a literal secret into the image")
        elif n == "EXPOSE":
            ports = [p.split("/")[0] for p in a.split()]
            if "22" in ports:
                add("DS014", ins.line, "Port 22 (SSH) is exposed")
        elif n in ("CMD", "ENTRYPOINT"):
            stage["cmd" if n == "CMD" else "entry"].append(ins.line)
            if a and not a.startswith("["):
                add("DS017", ins.line, f"{n} uses shell form")
        elif n == "USER":
            stage["user"] = (ins.line, a)
        elif n == "HEALTHCHECK":
            stage["health"] = True
        elif n == "MAINTAINER":
            add("DS018", ins.line, "MAINTAINER is deprecated")

    for st in stages:
        for key, label in (("cmd", "CMD"), ("entry", "ENTRYPOINT")):
            if len(st[key]) > 1:
                add("DS012", st[key][-1],
                    f"{len(st[key])} {label} instructions in one stage; only the last one counts")

    if stages:
        final = stages[-1]
        from_line = final["from"].line
        if final["user"] is None:
            add("DS002", from_line, "No USER instruction: the container runs as root")
        else:
            uline, uval = final["user"]
            if uval.split(":")[0].strip().lower() in ("root", "0"):
                add("DS002", uline, "The final USER is root")
        if not final["health"]:
            add("DS015", from_line, "The final stage has no HEALTHCHECK")

    return sorted(out, key=lambda f: (f.line, f.rule))


def find_dockerfiles(path: Path) -> List[Path]:
    if not path.is_dir():
        return [path]
    found = []
    for p in sorted(path.rglob("*")):
        if not p.is_file() or ".git" in p.parts or "node_modules" in p.parts:
            continue
        n = p.name
        if n == "Dockerfile" or n.startswith("Dockerfile.") or n.lower().endswith(".dockerfile"):
            found.append(p)
    return found


COLORS = {"error": "\033[31m", "warning": "\033[33m", "info": "\033[36m"}


def render_text(results: List[Tuple[str, List[Finding]]], color: bool) -> str:
    lines: List[str] = []
    counts = {"error": 0, "warning": 0, "info": 0}
    for name, findings in results:
        for f in findings:
            counts[f.severity] += 1
            tag = f.severity.upper().ljust(7)
            if color:
                tag = f"{COLORS[f.severity]}{tag}\033[0m"
            lines.append(f"{name}:{f.line}: {tag} {f.rule} {f.message}")
            lines.append(f"    hint: {f.hint}")
    total = sum(counts.values())
    summary = (f"{len(results)} file(s) checked: {counts['error']} error(s), "
               f"{counts['warning']} warning(s), {counts['info']} info")
    if total == 0:
        summary = f"{len(results)} file(s) checked: no problems found"
    lines.append(summary)
    return "\n".join(lines)


def render_github(results: List[Tuple[str, List[Finding]]]) -> str:
    level = {"error": "error", "warning": "warning", "info": "notice"}
    return "\n".join(
        f"::{level[f.severity]} file={name},line={f.line},title={f.rule}::{f.message}"
        for name, findings in results for f in findings
    )


def render_json(results: List[Tuple[str, List[Finding]]]) -> str:
    summary = {"error": 0, "warning": 0, "info": 0}
    files = []
    for name, findings in results:
        for f in findings:
            summary[f.severity] += 1
        files.append({"file": name, "findings": [asdict(f) for f in findings]})
    return json.dumps({"version": __version__, "files": files, "summary": summary}, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="dockerscope", description="Static linter for Dockerfiles.")
    p.add_argument("paths", nargs="*", help="Dockerfiles or folders ('-' reads stdin). Default: current folder.")
    p.add_argument("-f", "--format", choices=("text", "json", "github"), default="text")
    p.add_argument("-i", "--ignore", action="append", default=[], metavar="RULE",
                   help="Rule id(s) to skip, comma separated. Repeatable.")
    p.add_argument("--fail-on", choices=("info", "warning", "error", "never"), default="warning",
                   help="Lowest severity that makes the exit code 1 (default: warning).")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-rules", action="store_true", help="Show every rule and exit.")
    p.add_argument("-V", "--version", action="version", version=f"dockerscope {__version__}")
    a = p.parse_args(argv)

    if a.list_rules:
        for rid, (sev, title, _hint) in RULES.items():
            print(f"{rid}  {sev.ljust(7)}  {title}")
        return 0

    ignore = {r.strip().upper() for chunk in a.ignore for r in chunk.split(",") if r.strip()}
    files: List[str] = []
    for raw in a.paths or ["."]:
        if raw == "-":
            files.append("-")
            continue
        path = Path(raw)
        if not path.exists():
            print(f"dockerscope: no such file or folder: {raw}", file=sys.stderr)
            return 2
        files.extend(str(x) for x in find_dockerfiles(path))
    if not files:
        print("dockerscope: no Dockerfiles found", file=sys.stderr)
        return 2

    results: List[Tuple[str, List[Finding]]] = []
    for f in files:
        if f == "-":
            text, name = sys.stdin.read(), "<stdin>"
        else:
            text, name = Path(f).read_text(encoding="utf-8", errors="replace"), f
        results.append((name, [x for x in lint(text, name) if x.rule not in ignore]))

    color = (not a.no_color) and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if a.format == "json":
        print(render_json(results))
    elif a.format == "github":
        out = render_github(results)
        if out:
            print(out)
    else:
        print(render_text(results, color))

    if a.fail_on == "never":
        return 0
    worst = max((SEV_RANK[f.severity] for _, fs in results for f in fs), default=-1)
    return 1 if worst >= SEV_RANK[a.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
