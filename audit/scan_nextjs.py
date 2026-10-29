"""Heuristic scan of a Next.js source tree for service-role key misuse.

It looks for three patterns that RLS cannot protect against, because the service role key
bypasses RLS entirely:

  NX1  a service/secret key in a NEXT_PUBLIC_ variable (Next.js inlines these into the
       browser bundle at build time)
  NX2  a client component ('use client') that uses the service role key, directly or through
       a local module it imports
  NX3  server code (route handler or 'use server') that uses the service role key, reads input
       from the request, and never calls auth.getUser() to identify the caller

It is a grep with some import resolution, not a parser. It finds candidates for a human to read;
a clean result does not prove the app is safe. Usage:

    python -m audit.scan_nextjs <path-to-next-app>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SOURCE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", ".next", ".git", "dist", "build"}

PUBLIC_SECRET = re.compile(r"\bNEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SERVICE_KEY|SECRET|PRIVATE)[A-Z0-9_]*")
SERVICE_ROLE = re.compile(r"SERVICE_ROLE|service_role", re.I)
USE_CLIENT = re.compile(r"^\s*(['\"])use client\1", re.M)
USE_SERVER = re.compile(r"^\s*(['\"])use server\1", re.M)
IMPORT_FROM = re.compile(r"""(?:import|export)[^'"]*?from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"]""")
REQUEST_INPUT = re.compile(r"\b(req|request)\.(json|formData|text)\(\)|searchParams|params\.")
GET_USER = re.compile(r"auth\.getUser\(")


def _files(root: Path):
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and (path.suffix in SOURCE_EXT or path.name.startswith(".env")):
            yield path


def _resolve(spec: str, importer: Path, root: Path) -> Path | None:
    if spec.startswith("@/"):
        base = root / spec[2:]
    elif spec.startswith("."):
        base = (importer.parent / spec).resolve()
    else:
        return None
    for cand in [base, *(base.with_suffix(ext) for ext in SOURCE_EXT),
                 *(base / f"index{ext}" for ext in SOURCE_EXT)]:
        if cand.is_file():
            return cand.resolve()
    return None


def scan(root: str | Path) -> list[dict]:
    root = Path(root).resolve()
    texts = {p.resolve(): p.read_text(encoding="utf-8", errors="replace") for p in _files(root)}
    rel = lambda p: p.relative_to(root).as_posix()  # noqa: E731
    findings: list[dict] = []

    # NX1
    for path, text in texts.items():
        for lineno, line in enumerate(text.splitlines(), 1):
            m = PUBLIC_SECRET.search(line)
            if m:
                findings.append({"rule": "NX1", "level": "FAIL", "file": rel(path), "line": lineno,
                                 "detail": f"{m.group(0)} is inlined into the browser bundle"})

    uses_service = {p for p, t in texts.items() if p.suffix in SOURCE_EXT and SERVICE_ROLE.search(t)}

    def imports_service(path: Path) -> list[str]:
        hits = []
        for m in IMPORT_FROM.finditer(texts[path]):
            target = _resolve(m.group(1) or m.group(2), path, root)
            if target in uses_service:
                hits.append(rel(target))
        return hits

    for path, text in texts.items():
        if path.suffix not in SOURCE_EXT:
            continue
        direct = path in uses_service
        via = imports_service(path)
        if not (direct or via):
            continue
        how = "uses the service role key" + (f" via {', '.join(via)}" if via else "")
        # NX2
        if USE_CLIENT.search(text):
            findings.append({"rule": "NX2", "level": "FAIL", "file": rel(path), "line": None,
                             "detail": f"client component {how}"})
        # NX3
        is_server_entry = path.stem == "route" or USE_SERVER.search(text)
        if is_server_entry and REQUEST_INPUT.search(text) and not GET_USER.search(text):
            findings.append({"rule": "NX3", "level": "REVIEW", "file": rel(path), "line": None,
                             "detail": f"server code {how}, reads request input and never calls "
                                       "auth.getUser(): who is the caller, and which tenant?"})
    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(scan(target), indent=2))
