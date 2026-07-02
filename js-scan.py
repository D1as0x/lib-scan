#!/usr/bin/env python3
import textwrap
import shutil
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

JS_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
NPM_REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/npmrepository.json"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
SNYK_URL = "https://security.snyk.io/vuln?search={}"


def cve_links(cve):
    return {"cve": cve, "nvd": NVD_URL.format(cve), "snyk": SNYK_URL.format(cve)}


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for k in list(vars(cls)):
            if k.isupper():
                setattr(cls, k, "")


def sev_color(sev):
    return {
        "critical": C.MAGENTA,
        "high": C.RED,
        "medium": C.YELLOW,
        "low": C.CYAN,
        "none": C.GREY,
    }.get(sev, C.GREY)


def load_repo(offline, db_paths):
    repo = {}
    sources = []

    if offline:
        if not db_paths:
            fatal("Modo --offline exige --db com o(s) arquivo(s) de definicoes.")
        for p in db_paths:
            sources.append(("file", p))
    else:
        sources = [("url", JS_REPO_URL), ("url", NPM_REPO_URL)]

    for kind, src in sources:
        try:
            if kind == "url":
                with urllib.request.urlopen(src, timeout=30) as r:
                    data = json.loads(r.read().decode("utf-8"))
            else:
                with open(src, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except Exception as e:
            warn(f"Falha ao carregar definicoes de {src}: {e}")
            continue
        for name, entry in data.items():
            repo.setdefault(name, entry)

    if not repo:
        fatal("Nenhuma definicao de vulnerabilidade carregada.")
    return repo


def _to_comparable(version):
    parts = re.split(r"[.\-]", str(version))
    out = []
    for p in parts:
        if p.isdigit():
            out.append(int(p))
        else:
            out.append(p)
    return out


def version_compare(a, b):
    va, vb = _to_comparable(a), _to_comparable(b)
    for i in range(max(len(va), len(vb))):
        pa = va[i] if i < len(va) else 0
        pb = vb[i] if i < len(vb) else 0
        if isinstance(pa, int) and isinstance(pb, int):
            if pa != pb:
                return -1 if pa < pb else 1
        elif isinstance(pa, int) and isinstance(pb, str):
            return 1
        elif isinstance(pa, str) and isinstance(pb, int):
            return -1
        else:
            if pa != pb:
                return -1 if pa < pb else 1
    return 0


def is_at_or_above(v, bound):
    return version_compare(v, bound) >= 0


def is_above(v, bound):
    return version_compare(v, bound) > 0


def is_below(v, bound):
    return version_compare(v, bound) < 0


def is_at_or_below(v, bound):
    return version_compare(v, bound) <= 0


def vuln_matches(version, vuln):
    ok = True
    if "atOrAbove" in vuln:
        ok = ok and is_at_or_above(version, vuln["atOrAbove"])
    if "above" in vuln:
        ok = ok and is_above(version, vuln["above"])
    if "below" in vuln:
        ok = ok and is_below(version, vuln["below"])
    if "atOrBelow" in vuln:
        ok = ok and is_at_or_below(version, vuln["atOrBelow"])
    return ok


VERSION_RE = r"[0-9][0-9.a-z_\-]+"
VERSION_TOKEN = "§§version§§"


def _expand_named(pattern):
    return pattern.replace(VERSION_TOKEN, f"(?P<version>{VERSION_RE})")


def _safe_finditer(pattern, content):
    try:
        return list(re.finditer(pattern, content))
    except re.error:
        return []


def detect_in_content(content, entry):
    versions = set()
    extractors = entry.get("extractors", {})
    for pattern in extractors.get("filecontent", []):
        for m in _safe_finditer(_expand_named(pattern), content):
            if m.groupdict().get("version"):
                versions.add(m.group("version"))
    for pattern in extractors.get("filecontentreplace", []):
        try:
            _, rx, repl, _ = pattern.split("/")
            rx = rx.replace(VERSION_TOKEN, f"({VERSION_RE})")
            m = re.search(rx, content)
            if m:
                versions.add(m.expand(re.sub(r"\$(\d)", r"\\\1", repl)))
        except (re.error, ValueError):
            continue
    return versions


def detect_in_filename(filename, entry):
    versions = set()
    for pattern in entry.get("extractors", {}).get("filename", []):
        for m in _safe_finditer(_expand_named(pattern), filename):
            if m.groupdict().get("version"):
                versions.add(m.group("version"))
    return versions


def detect_by_hash(content_bytes, entry):
    versions = set()
    hashes = entry.get("extractors", {}).get("hashes", {})
    if hashes:
        h = hashlib.sha1(content_bytes).hexdigest()
        if h in hashes:
            versions.add(hashes[h])
    return versions


def scan_content(raw, fname, source, repo):
    findings = []
    text = raw.decode("utf-8", errors="ignore")
    for name, entry in repo.items():
        versions = set()
        versions |= detect_in_filename(fname, entry)
        versions |= detect_in_content(text, entry)
        versions |= detect_by_hash(raw, entry)
        for v in versions:
            findings.extend(build_findings(name, v, source, repo))
    return findings


def scan_js_file(path, repo):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except Exception as e:
        warn(f"Nao foi possivel ler {path}: {e}")
        return []
    return scan_content(raw, os.path.basename(path), path, repo)


USER_AGENT = "jsvulnscan/1.0"


def normalize_url(url):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "https://" + url
    return url


def fetch_url(url, timeout=30):
    url = normalize_url(url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ctype = r.headers.get("Content-Type", "")
            return r.read(), ctype
    except Exception as e:
        warn(f"Falha ao baixar {url}: {e}")
        return None, ""


def _resolve_url(base, src):
    from urllib.parse import urljoin
    return urljoin(base, src)


def extract_script_srcs(html, base_url):
    srcs = []
    for m in re.finditer(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',
                          html, re.IGNORECASE):
        srcs.append(_resolve_url(base_url, m.group(1)))
    return srcs


def scan_url(url, repo):
    findings = []
    url = normalize_url(url)
    raw, ctype = fetch_url(url)
    if raw is None:
        return findings

    looks_html = "html" in ctype.lower() or (
        not url.rstrip("/").lower().endswith((".js", ".mjs"))
        and raw.lstrip()[:1] == b"<"
    )

    if looks_html:
        html = raw.decode("utf-8", errors="ignore")
        findings.extend(scan_content(raw, url, url, repo))
        srcs = extract_script_srcs(html, url)
        if not srcs:
            warn(f"Nenhum <script src> encontrado em {url}")
        for src in srcs:
            js_raw, _ = fetch_url(src)
            if js_raw is not None:
                fname = os.path.basename(src.split("?")[0])
                findings.extend(scan_content(js_raw, fname, src, repo))
    else:
        fname = os.path.basename(url.split("?")[0])
        findings.extend(scan_content(raw, fname, url, repo))
    return findings


def parse_package_json(path):
    deps = {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return deps
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, ver in (data.get(key) or {}).items():
            clean = re.sub(r"^[\^~>=<\s]*", "", str(ver)).split(" ")[0]
            if re.match(r"^\d", clean):
                deps[name] = clean
    return deps


def parse_package_lock(path):
    deps = {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return deps

    for pkgpath, meta in (data.get("packages") or {}).items():
        if not pkgpath:
            continue
        name = pkgpath.split("node_modules/")[-1]
        if meta.get("version"):
            deps[name] = meta["version"]

    def walk(d):
        for name, meta in (d or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                deps.setdefault(name, meta["version"])
                walk(meta.get("dependencies"))
    walk(data.get("dependencies"))
    return deps


def parse_yarn_lock(path):
    deps = {}
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return deps
    blocks = re.split(r"\n(?=\S)", text)
    for block in blocks:
        header = block.splitlines()[0] if block.strip() else ""
        m = re.match(r'"?(@?[^@\s"]+)@', header)
        vm = re.search(r'\n\s+version:?\s+"?([0-9][^"\s]*)"?', block)
        if m and vm:
            deps[m.group(1)] = vm.group(1)
    return deps


def scan_manifest(deps, source_path, repo):
    findings = []
    for name, version in deps.items():
        if name in repo:
            findings.extend(build_findings(name, version, source_path, repo))
    return findings


def build_findings(component, version, source, repo):
    entry = repo.get(component, {})
    results = []
    for vuln in entry.get("vulnerabilities", []):
        if not vuln_matches(version, vuln):
            continue
        ident = vuln.get("identifiers", {})
        cves = ident.get("CVE", [])
        summary = ident.get("summary") or (vuln.get("info") or [""])[0]
        results.append({
            "component": component,
            "version": version,
            "severity": (vuln.get("severity") or "none").lower(),
            "cves": cves,
            "cve_refs": [cve_links(c) for c in cves],
            "summary": summary,
            "info": vuln.get("info", []),
            "below": vuln.get("below") or vuln.get("atOrBelow") or "",
            "source": source,
        })
    return results


IGNORE_DIRS = {".git", ".hg", ".svn"}


def collect_targets(root):
    js_files, manifests = [], []
    if os.path.isfile(root):
        _classify(root, js_files, manifests)
        return js_files, manifests
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fn in filenames:
            _classify(os.path.join(dirpath, fn), js_files, manifests)
    return js_files, manifests


def _classify(path, js_files, manifests):
    base = os.path.basename(path)
    if base in ("package.json", "package-lock.json", "yarn.lock"):
        manifests.append(path)
    elif base.endswith(".js") or base.endswith(".mjs"):
        js_files.append(path)


def dedupe(findings):
    seen, out = set(), []
    for f in findings:
        key = (f["component"], f["version"], tuple(f["cves"]), f["summary"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), x["component"]))
    return out


def sev_badge(sev):
    color = sev_color(sev)
    return f"{color}{C.BOLD}{sev.upper():<8}{C.RESET}"


def print_report(findings, scanned_js, scanned_manifests, scanned_urls=0):
    print()
    print(f"{C.BOLD}{C.CYAN}  jsvulnscan — scanner de vulnerabilidades JS{C.RESET}")
    print(f"{C.GREY}  {'-' * 60}{C.RESET}")
    if scanned_urls:
        print(f"{C.GREY}  URLs analisadas        : {scanned_urls}{C.RESET}")
    print(f"{C.GREY}  Arquivos JS analisados : {scanned_js}{C.RESET}")
    print(f"{C.GREY}  Manifestos analisados  : {scanned_manifests}{C.RESET}")
    print()

    if not findings:
        print(f"  {C.GREEN}{C.BOLD}✓ Nenhuma vulnerabilidade conhecida encontrada.{C.RESET}\n")
        return

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    for f in findings:
        color = sev_color(f["severity"])
        print(f"  {sev_badge(f['severity'])} {C.BOLD}{f['component']}{C.RESET} "
              f"{C.DIM}{f['version']}{C.RESET}")
        if f["below"]:
            print(f"           {C.GREY}Corrigido em: >= {f['below']}{C.RESET}")
        if f["cves"]:
            for c in f["cves"]:
                print(f"           {color}CVE:{C.RESET} {c}")
                print(f"           {C.BLUE}NVD : {NVD_URL.format(c)}{C.RESET}")
                print(f"           {C.BLUE}Snyk: {SNYK_URL.format(c)}{C.RESET}")
        else:
            print(f"           {color}CVE:{C.RESET} sem CVE atribuido")
        for url in f["info"][:2]:
            print(f"           {C.BLUE}{url}{C.RESET}")
        print(f"           {C.GREY}origem: {f['source']}{C.RESET}")
        if f["summary"]:
            terminal_width = shutil.get_terminal_size((100, 20)).columns
            setback = "           "
            summary_formatado = textwrap.fill(
                f["summary"].strip(),
                width=terminal_width,
                initial_indent=setback,
                subsequent_indent=setback
            )
            print(f"{C.GREY}{summary_formatado}{C.RESET}")
        print()

    print(f"{C.GREY}  {'-' * 60}{C.RESET}")
    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "none"):
        if counts.get(sev):
            summary_parts.append(f"{sev_color(sev)}{counts[sev]} {sev}{C.RESET}")
    print(f"  {C.BOLD}Total: {len(findings)} vulnerabilidade(s){C.RESET}  "
          f"[ {' | '.join(summary_parts)} ]")
    print()


def print_json(findings):
    print(json.dumps(findings, indent=2, ensure_ascii=False))


def write_cve_docx(findings, path="cves.docx"):
    import subprocess
    import tempfile

    seen, items = set(), []
    for f in findings:
        for c in f["cves"]:
            if c not in seen:
                seen.add(c)
                items.append({"cve": c, "url": NVD_URL.format(c)})

    node_script = r"""
const { Document, Packer, Paragraph, TextRun, ExternalHyperlink } = require("docx");
const fs = require("fs");
const items = JSON.parse(process.argv[2]);
const out = process.argv[3];
const paras = items.map(it => new Paragraph({
  children: [
    new ExternalHyperlink({
      link: it.url,
      children: [new TextRun({ text: it.cve, style: "Hyperlink" })],
    }),
  ],
}));
if (paras.length === 0) {
  paras.push(new Paragraph({ children: [new TextRun("Nenhum CVE encontrado.")] }));
}
const doc = new Document({ sections: [{ children: paras }] });
Packer.toBuffer(doc).then(b => fs.writeFileSync(out, b));
"""

    script_dir = os.path.dirname(os.path.abspath(__file__))
    node_modules = os.path.join(script_dir, "node_modules", "docx")
    if not os.path.isdir(node_modules):
        fatal("A biblioteca 'docx' do Node nao foi encontrada. Na pasta do "
              f"script, rode: (cd {script_dir} && npm install docx)")

    fd, js_path = tempfile.mkstemp(suffix=".js", dir=script_dir)
    try:
        with os.fdopen(fd, "w") as tf:
            tf.write(node_script)
        subprocess.run(
            ["node", js_path, json.dumps(items), os.path.abspath(path)],
            check=True,
            cwd=script_dir,
        )
    except Exception as e:
        fatal(f"Falha ao gerar o .docx: {e}")
    finally:
        os.unlink(js_path)

    print(f"Arquivo gerado: {path}")
    print("Arraste-o para o Google Drive e abra com o Google Docs (ou Arquivo > "
          "Abrir). Os CVEs ficam clicaveis, cada um levando ao site do NIST.")


def warn(msg):
    print(f"{C.YELLOW}[aviso]{C.RESET} {msg}", file=sys.stderr)


def fatal(msg):
    print(f"{C.RED}[erro]{C.RESET} {msg}", file=sys.stderr)
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="Scanner de vulnerabilidades em bibliotecas JS")
    ap.add_argument("path", nargs="?", help="Arquivo ou diretorio a escanear")
    ap.add_argument("-u", "--url", action="append", default=[],
                    help="URL a escanear (arquivo .js ou pagina HTML). Pode repetir.")
    ap.add_argument("--json", action="store_true", help="Saida em JSON")
    ap.add_argument("--cve-docx", action="store_true",
                    help="Gera cves.docx com os CVEs clicaveis (para o Google Docs)")
    ap.add_argument("--no-color", action="store_true", help="Desativa cores")
    ap.add_argument("--offline", action="store_true", help="Usa base local (--db) em vez de baixar")
    ap.add_argument("--db", help="Arquivo(s) de definicoes locais, separados por virgula")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None,
                    help="Sai com codigo !=0 se houver achado >= severidade dada")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if not args.path and not args.url:
        fatal("Informe um caminho ou pelo menos uma --url (-u).")
    if args.path and not os.path.exists(args.path):
        fatal(f"Caminho nao encontrado: {args.path}")

    db_paths = args.db.split(",") if args.db else []
    repo = load_repo(args.offline, db_paths)

    js_files, manifests = collect_targets(args.path) if args.path else ([], [])
    findings = []
    for url in args.url:
        findings.extend(scan_url(url, repo))
    for jf in js_files:
        findings.extend(scan_js_file(jf, repo))
    for mf in manifests:
        base = os.path.basename(mf)
        if base == "package.json":
            deps = parse_package_json(mf)
        elif base == "package-lock.json":
            deps = parse_package_lock(mf)
        else:
            deps = parse_yarn_lock(mf)
        findings.extend(scan_manifest(deps, mf, repo))

    findings = dedupe(findings)

    if args.cve_docx:
        write_cve_docx(findings)
    elif args.json:
        print_json(findings)
    else:
        print_report(findings, len(js_files), len(manifests), len(args.url))

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold for f in findings):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)