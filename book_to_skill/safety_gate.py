"""Deterministic safety gate for the document -> context -> skill supply chain.

Three checks, all rule-based, stdlib-only, and free of time, randomness or
network, so the same input always yields the same findings:

* :func:`classify_text` -- classifies extracted document text (or generated
  skill Markdown) for prompt-injection and exfiltration shapes. The extractor
  calls it before ``full_text.txt`` is written, so blocked content never
  reaches the agent unless the user opts in with ``--safety-override``.
* :func:`audit_converter` -- audits the converter's own source tree for
  phone-home and payload-smuggling shapes (network imports, shell-outs that are
  not on the allowlist, decoders of embedded blobs, secret/wallet path
  literals, unknown URLs, binary files). The extractor runs it on every start
  and refuses to extract when it blocks; CI runs it on every push.
* The generated-skill scanner in ``tools/scan_generated_skill.py`` imports its
  rule tables from here, so the three layers cannot drift apart.

Findings report a rule id and a location, never the matched text: the matched
text is the untrusted payload, and echoing it would hand it to the agent.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence
from urllib.parse import urlsplit

from book_to_skill.sanitize import is_invisible_codepoint

# In the converter's own source, joiners inside Sinhala/Persian literals and
# comments, emoji variation selectors and a BOM in a comment are legitimate and
# Python ignores them at runtime; the executable paths are covered by the AST
# rules. What must still block in source is the Trojan Source class (bidi
# controls) and the payload carriers (tag block, invisible letters, annotation
# controls), which is everything is_invisible_codepoint() flags except these.
_SOURCE_TOLERATED_CODEPOINTS = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD})
_SOURCE_TOLERATED_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))
# SKILL.md is executed by the agent, so only emoji sequences are tolerated there.
_MARKDOWN_TOLERATED_CODEPOINTS = frozenset({0x200D, 0xFE0F})


def _source_invisible(codepoint: int, *, markdown: bool) -> bool:
    if not is_invisible_codepoint(codepoint):
        return False
    if markdown:
        return codepoint not in _MARKDOWN_TOLERATED_CODEPOINTS
    if codepoint in _SOURCE_TOLERATED_CODEPOINTS:
        return False
    return not any(low <= codepoint <= high for low, high in _SOURCE_TOLERATED_RANGES)

RULES_VERSION = "1"

BLOCK = "block"
WARN = "warn"
PASS = "pass"

# Exit codes shared by tools/safety_gate.py and the extractor, so SKILL.md can
# branch on them without parsing prose.
EXIT_PASS = 0
EXIT_BLOCK = 1
EXIT_INCOMPLETE = 2
EXTRACT_EXIT_CONTENT_BLOCKED = 3
EXTRACT_EXIT_SELF_AUDIT_FAILED = 4

SAFETY_FILENAME = "safety.json"
QUARANTINE_FILENAME = "quarantined_text.txt"


class GateError(RuntimeError):
    """Raised when a check cannot be completed, so its result is unknown."""


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    message: str

    @property
    def severity(self) -> str:
        return BLOCK if rule_id_is_blocking(self.rule_id) else WARN


# ---------------------------------------------------------------------------
# Content rules. Shared with tools/scan_generated_skill.py.
# ---------------------------------------------------------------------------

# Prose-shaped rules. Advisory on their own: a book about prompt engineering
# legitimately quotes them, so the gate reports them as WARN and lets the
# human decide.
_CONTENT_RULES = (
    (
        "prompt.ignore_previous",
        re.compile(
            r"\bignore\s+(?:(?:all|any|the)\s+)?(?:previous|prior)\s+"
            r"(?:instructions?|prompts?|rules?|messages?)\b",
            re.IGNORECASE,
        ),
        "contains an instruction-override phrase",
    ),
    (
        "prompt.disregard_system",
        re.compile(r"\bdisregard\s+(?:the\s+)?(?:system|developer)\b", re.IGNORECASE),
        "contains a system-instruction override phrase",
    ),
    (
        "prompt.role_reassignment",
        re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
        "contains a role-reassignment phrase",
    ),
    (
        "prompt.fake_system_prefix",
        re.compile(r"^\s*(?:[-*]\s*)?(?:system|developer)\s*:", re.IGNORECASE),
        "contains a system-like message prefix",
    ),
    (
        "prompt.system_tag",
        re.compile(r"<\s*/?\s*system\b[^>]*>", re.IGNORECASE),
        "contains a system-message tag",
    ),
    (
        "prompt.chat_template_tag",
        re.compile(r"<\|\s*im_start\s*\|>|\[\s*INST\s*\]", re.IGNORECASE),
        "contains a model chat-template delimiter",
    ),
    (
        # Only the delimited forms -- a token, not the English phrase. The
        # families below are the ones that appear in real chat templates and
        # tool-calling protocols:
        #
        #   <tool_call> ... </tool_call>   Hermes / Qwen style
        #   <|tool_call|>                  special-token style
        #   [TOOL_CALL] / [/tool_call]     bracket style
        #   {{tool_call}}                  template placeholder
        #   "tool_call"                    JSON key or value
        #
        # Matching bare prose instead fired on every book that explains what a
        # tool call is -- the agent and prompting books this converter is most
        # used on. A gate that always trips on a whole category teaches people
        # to wave it through, which costs more than the false positive itself.
        "prompt.tool_call_tag",
        re.compile(
            r"""<\|?\s*/?\s*tool[_ -]?call\s*\|?>      # <tool_call>, </tool_call>, <|tool_call|>
              | \[\s*/?\s*tool[_ -]?call\s*\]          # [TOOL_CALL], [/tool_call]
              | \{\{\s*/?\s*tool[_ -]?call\s*\}\}      # {{tool_call}}
              | "\s*tool[_ -]?call\s*"                 # JSON key or value
            """,
            re.IGNORECASE | re.VERBOSE,
        ),
        "contains a tool-call control token",
    ),
    (
        "prompt.hidden_from_user",
        re.compile(
            r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|alert|notify|mention\s+(?:this\s+)?to|"
            r"reveal\s+(?:this\s+)?to)\s+the\s+(?:user|human|operator)\b",
            re.IGNORECASE,
        ),
        "contains a concealment instruction aimed at the agent",
    ),
    (
        "prompt.addresses_ai",
        re.compile(
            r"\b(?:if\s+you\s+are|attention|note\s+to|instructions?\s+for)\s+"
            r"(?:an?\s+|the\s+)?(?:ai|llm|language\s+model|assistant|agent|claude|copilot|gpt)s?\b",
            re.IGNORECASE,
        ),
        "contains text addressed to an AI reader",
    ),
    (
        "prompt.system_prompt_reveal",
        re.compile(
            r"\b(?:reveal|print|output|repeat|show|dump)\s+(?:your|the)\s+"
            r"(?:system|developer|initial)\s+(?:prompt|instructions?)\b",
            re.IGNORECASE,
        ),
        "contains a system-prompt disclosure request",
    ),
    (
        "prompt.html_comment_instruction",
        re.compile(
            r"<!--[^>]*\b(?:ignore|instruction|system|assistant|you\s+must|do\s+not)\b",
            re.IGNORECASE,
        ),
        "contains an HTML comment carrying instruction language (hidden when rendered)",
    ),
)

# Executable-shaped rules. These never belong in extracted prose or a generated
# reference skill, so they block without a human in the loop.
_EXECUTABLE_RULES = (
    (
        "shell.pipe_to_shell",
        re.compile(
            r"\b(?:curl|wget|fetch)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|)sh\b"
            r"|\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?python3?\b",
            re.IGNORECASE,
        ),
        "contains a download-and-execute pipeline",
    ),
    (
        "shell.decode_payload",
        re.compile(
            r"\bbase64\s+(?:-d|-D|--decode)\b"
            r"|\becho\s+[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*\|",
            re.IGNORECASE,
        ),
        "contains a decode-and-run payload shape",
    ),
    (
        "net.data_uri",
        re.compile(r"\bdata:[a-z0-9.+/-]+;base64,", re.IGNORECASE),
        "contains a base64 data URI",
    ),
    (
        "net.exfil_url",
        re.compile(
            r"https?://\S*\?\S*\b(?:token|secret|key|password|passwd|env|cookie|session|auth)=",
            re.IGNORECASE,
        ),
        "contains a URL whose query string carries a secret-shaped parameter",
    ),
)

_EXFILTRATION_TERM = re.compile(r"\bexfiltrat(?:e|es|ed|ing|ion)\b", re.IGNORECASE)
_OUTBOUND_TERM = re.compile(
    r"\b(?:curl|wget|send|post|upload|transmit)\b|https?://",
    re.IGNORECASE,
)
_SENSITIVE_TERM = re.compile(
    r"(?:\.env\b|\bbase64\b|\bsecrets?\b|\bcredentials?\b|\bapi[_ -]?keys?\b)",
    re.IGNORECASE,
)

# A long run drawn only from the base64 alphabet is an opaque payload, not
# prose. 400 characters is well past any URL or identifier a book prints.
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9+/]{400,}={0,2}")

# Rule ids whose findings block on their own. Everything else is advisory.
BLOCKING_RULE_PREFIXES = ("shell.", "net.", "self.", "unicode.", "frontmatter.")
BLOCKING_RULE_IDS = frozenset({
    "prompt.system_tag",
    "prompt.chat_template_tag",
    "prompt.tool_call_tag",
    "tool.exfiltration_shape",
})


def rule_id_is_blocking(rule_id: str) -> bool:
    return rule_id in BLOCKING_RULE_IDS or rule_id.startswith(BLOCKING_RULE_PREFIXES)


def classify_text(text: str, path: str = "full_text.txt") -> list[Finding]:
    """Classify one body of text line by line. Deterministic and side-effect free."""
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        invisible = sorted({ord(char) for char in line if is_invisible_codepoint(ord(char))})
        if invisible:
            codepoints = ", ".join(f"U+{value:04X}" for value in invisible)
            findings.append(Finding(
                path, line_number, "unicode.invisible",
                f"contains invisible Unicode code point(s): {codepoints}",
            ))
        for rule_id, pattern, message in _CONTENT_RULES + _EXECUTABLE_RULES:
            if pattern.search(line):
                findings.append(Finding(path, line_number, rule_id, message))
        if _EXFILTRATION_TERM.search(line) or (
            _OUTBOUND_TERM.search(line) and _SENSITIVE_TERM.search(line)
        ):
            findings.append(Finding(
                path, line_number, "tool.exfiltration_shape",
                "contains exfiltration-shaped tool or sensitive-data language",
            ))
        if _OPAQUE_RUN.search(line):
            findings.append(Finding(
                path, line_number, "encoding.opaque_run",
                "contains a long opaque base64-alphabet run",
            ))
    return sorted(findings, key=_finding_key)


def _finding_key(finding: Finding) -> tuple:
    return (finding.path.lower(), finding.line, finding.rule_id)


def verdict_for(findings: Iterable[Finding]) -> str:
    worst = PASS
    for finding in findings:
        if finding.severity == BLOCK:
            return BLOCK
        worst = WARN
    return worst


def report_dict(findings: Sequence[Finding], **extra) -> dict:
    """JSON-ready report. Key order is fixed so two runs diff clean."""
    payload = {
        "rules_version": RULES_VERSION,
        "verdict": verdict_for(findings),
        "blocking": sum(1 for f in findings if f.severity == BLOCK),
        "advisory": sum(1 for f in findings if f.severity == WARN),
        "findings": [
            {**asdict(f), "severity": f.severity}
            for f in sorted(findings, key=_finding_key)
        ],
    }
    payload.update(extra)
    return payload


def dump_report(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# Converter self-audit.
# ---------------------------------------------------------------------------

# Everything the converter legitimately shells out to. Anything else blocks.
ALLOWED_COMMANDS = frozenset({"pdftotext", "pdfinfo", "ebook-convert", "git"})
ALLOWED_PYTHON_MODULES = frozenset({"pip"})  # sys.executable -m <module>

# Module roots the converter must never import. urllib.parse stays allowed;
# urllib.request and friends do not.
FORBIDDEN_IMPORTS = frozenset({
    "socket", "ssl", "select", "selectors",
    "urllib.request", "urllib.error", "urllib3", "http", "http.client", "http.server",
    "requests", "httpx", "aiohttp", "websocket", "websockets",
    "ftplib", "smtplib", "telnetlib", "xmlrpc", "imaplib", "poplib", "nntplib",
    "ctypes", "cffi", "pickle", "marshal", "shelve", "webbrowser",
    "multiprocessing.connection", "asyncio",
})

# Dotted call targets that decode, compile or execute hidden material.
FORBIDDEN_CALLS = frozenset({
    "eval", "exec", "compile", "__import__",
    "os.system", "os.popen",
    "importlib.import_module", "importlib.__import__",
    "base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode",
    "base64.b32decode", "base64.b16decode", "base64.a85decode", "base64.b85decode",
    "base64.decodebytes", "base64.decode",
    "zlib.decompress", "zlib.decompressobj", "lzma.decompress", "bz2.decompress",
    "gzip.decompress", "bytes.fromhex", "bytearray.fromhex", "codecs.decode",
    "codecs.escape_decode", "ctypes.CDLL", "ctypes.cdll",
})
FORBIDDEN_CALL_PREFIXES = ("os.exec", "os.spawn", "os.posix_spawn", "ctypes.")

SUBPROCESS_CALLS = frozenset({
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
})

_SECRET_ENV_KEY = re.compile(r"(?:KEY|TOKEN|SECRET|PASS|AUTH|CREDENTIAL|COOKIE)", re.IGNORECASE)

# Fragments that only appear in code that goes looking for wallets, browser
# profiles, or credentials. Matched case-insensitively against string literals
# in the converter's own source.
SENSITIVE_PATH_FRAGMENTS = (
    "local extension settings", "ledger live", "metamask", "phantom", "exodus",
    "electrum", "coinbase wallet", "trust wallet", "keystore", "wallet",
    "/.ssh", "id_rsa", "id_ed25519", ".aws/credentials", ".netrc", ".npmrc",
    ".pypirc", ".docker/config.json", "login data", "cookies", "keychain",
    "/library/application support/google/chrome", "/library/application support/firefox",
    "appdata/local/google/chrome", ".mozilla/firefox", ".config/google-chrome",
)

# Hosts the converter is allowed to name. Docs links and format namespaces only.
ALLOWED_HOSTS = frozenset({
    "calibre-ebook.com", "schemas.openxmlformats.org", "www.w3.org",
    "github.com", "docs.github.com", "cli.github.com", "pypi.org",
    "code.claude.com", "platform.claude.com", "docs.anthropic.com",
    "ampcode.com", "hermes-agent.nousresearch.com", "docs.openclaw.ai", "opencode.ai",
    "agentskills.io", "virgiliojr94.github.io",
})

_URL = re.compile(r"https?://[^\s\"'<>)\]`]+", re.IGNORECASE)


def _url_host(url: str) -> str:
    return urlsplit(url.rstrip(".,;:!?")).hostname or ""
_IP_PORT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b")
_HEX_ESCAPE_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_BASE64_BLOB = re.compile(r"^[A-Za-z0-9+/]{200,}={0,2}$")
_HEX_BLOB = re.compile(r"^[0-9A-Fa-f]{64,}$")

SUSPICIOUS_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".pyd", ".pyc", ".zip", ".tar", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".rar", ".bin", ".dat", ".sh", ".bash", ".zsh", ".ps1",
    ".bat", ".cmd", ".vbs", ".js", ".mjs", ".jar", ".dmg", ".pkg", ".msi", ".app",
})
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024

# Directories relative to the converter root that execute at runtime, plus the
# agent-executed spec. Tests and docs are out of scope: they never run on a
# user's machine during a conversion.
AUDIT_SURFACE = ("book_to_skill", "scripts", "tools", "SKILL.md")


def _dotted_name(node: ast.AST) -> str | None:
    """``a.b.c`` for Name/Attribute chains, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _import_is_forbidden(module: str) -> bool:
    return module in FORBIDDEN_IMPORTS or any(
        module.startswith(root + ".") for root in FORBIDDEN_IMPORTS
    )


def _call_is_forbidden(name: str) -> bool:
    return name in FORBIDDEN_CALLS or name.startswith(FORBIDDEN_CALL_PREFIXES)


def _argv_is_allowed(argv: ast.AST) -> bool:
    if not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts:
        return False
    first = argv.elts[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value in ALLOWED_COMMANDS
    if _dotted_name(first) == "sys.executable":
        constants = [
            elt.value for elt in argv.elts[1:3]
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        ]
        return len(constants) == 2 and constants[0] == "-m" and constants[1] in ALLOWED_PYTHON_MODULES
    return False


def _audit_python(relative: str, source: str) -> list[Finding]:
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError as exc:
        raise GateError(f"{relative} does not parse: line {exc.lineno}") from exc

    findings: list[Finding] = []

    def add(node: ast.AST, rule_id: str, message: str) -> None:
        findings.append(Finding(relative, getattr(node, "lineno", 0), rule_id, message))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _import_is_forbidden(alias.name):
                    add(node, "self.forbidden_import", f"imports {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _import_is_forbidden(module):
                add(node, "self.forbidden_import", f"imports from {module}")
            for alias in node.names:
                if _import_is_forbidden(f"{module}.{alias.name}" if module else alias.name):
                    add(node, "self.forbidden_import", f"imports {module}.{alias.name}")
        elif isinstance(node, ast.Call):
            name = _dotted_name(node.func)
            if name is None:
                continue
            if _call_is_forbidden(name):
                add(node, "self.forbidden_call", f"calls {name}")
            elif name in SUBPROCESS_CALLS:
                shell = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value
                    for kw in node.keywords
                )
                if shell:
                    add(node, "self.subprocess_shell", f"{name} with shell=True")
                elif not node.args or not _argv_is_allowed(node.args[0]):
                    add(node, "self.subprocess_unlisted", f"{name} with a command outside the allowlist")
            elif name in {"os.environ.get", "os.getenv"} and node.args:
                key = node.args[0]
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if _SECRET_ENV_KEY.search(key.value):
                        add(node, "self.secret_env", "reads a secret-shaped environment variable")
                else:
                    add(node, "self.env_dynamic_key", "reads an environment variable by a non-literal name")
        elif isinstance(node, ast.Subscript) and _dotted_name(node.value) == "os.environ":
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if _SECRET_ENV_KEY.search(key.value):
                    add(node, "self.secret_env", "reads a secret-shaped environment variable")
            else:
                add(node, "self.env_dynamic_key", "reads an environment variable by a non-literal name")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            findings.extend(_audit_literal(relative, node.lineno, node.value))

    findings.extend(_audit_raw_source(relative, source))
    return findings


# The one file whose string literals legitimately spell out the fragment list
# above. Only the fragment rule is relaxed for it: imports, calls, URLs,
# subprocess and blob rules still apply, so code added here to *use* such a
# path still has to get data out through a channel those rules block.
RULE_TABLE_FILE = "book_to_skill/safety_gate.py"


def _audit_literal(relative: str, line: int, value: str) -> list[Finding]:
    findings: list[Finding] = []
    lowered = value.lower()
    if relative != RULE_TABLE_FILE:
        for fragment in SENSITIVE_PATH_FRAGMENTS:
            if fragment in lowered:
                findings.append(Finding(relative, line, "self.sensitive_path", "names a credential, wallet or browser-profile path"))
                break
    if _BASE64_BLOB.match(value) or _HEX_BLOB.match(value):
        findings.append(Finding(relative, line, "self.opaque_literal", "contains an opaque encoded blob"))
    for url in _URL.findall(value):
        host = _url_host(url)
        if host not in ALLOWED_HOSTS:
            findings.append(Finding(relative, line, "self.unknown_host", "references a URL outside the allowed hosts"))
    if _IP_PORT.search(value):
        findings.append(Finding(relative, line, "self.ip_endpoint", "references a raw IP:port endpoint"))
    return findings


def _audit_raw_source(relative: str, source: str) -> list[Finding]:
    """Rules that must see the source text, not the parsed values."""
    findings: list[Finding] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if _HEX_ESCAPE_RUN.search(line):
            findings.append(Finding(relative, line_number, "self.hex_escape_run", "contains a long run of hex escapes"))
        if any(_source_invisible(ord(char), markdown=False) for char in line):
            findings.append(Finding(relative, line_number, "unicode.invisible", "contains a bidi control or invisible payload carrier"))
    return findings


def _audit_markdown(relative: str, text: str) -> list[Finding]:
    """SKILL.md is executed by the agent, so it gets the executable-shape rules
    plus the URL allowlist. Prose rules are skipped: the spec legitimately
    describes injection patterns to the agent."""
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if any(_source_invisible(ord(char), markdown=True) for char in line):
            findings.append(Finding(relative, line_number, "unicode.invisible", "contains invisible Unicode code point(s)"))
        for rule_id, pattern, message in _EXECUTABLE_RULES:
            if pattern.search(line):
                findings.append(Finding(relative, line_number, rule_id, message))
        for url in _URL.findall(line):
            host = _url_host(url)
            # Placeholders such as https://github.com/<owner>/<repo> parse to
            # github.com, which is allowed; a real foreign host is not.
            if host and host not in ALLOWED_HOSTS:
                findings.append(Finding(relative, line_number, "self.unknown_host", "references a URL outside the allowed hosts"))
    return findings


# Finder metadata is inert and present on every macOS checkout.
TOLERATED_HIDDEN_FILES = frozenset({".DS_Store"})
_PACKAGE_INSTALL_DIRS = frozenset({"site-packages", "dist-packages"})


def _is_package_install(root: Path) -> bool:
    """A pip/uv install compiles bytecode next to the sources it wrote, so
    there the two are equally trusted. Everywhere else (a git checkout, a
    skills-directory install) the entry points set ``sys.dont_write_bytecode``
    and no bytecode should exist at all."""
    return any(part in _PACKAGE_INSTALL_DIRS for part in root.parts)


def _walk_surface(root: Path) -> tuple[list[Path], list[Finding]]:
    """Files to audit, plus findings for entries that must not exist.

    Bytecode is reported, not skipped: Python loads a ``__pycache__/*.pyc``
    whose header matches the source's size and mtime *instead of* the source.
    The entry points defeat that by pointing ``sys.pycache_prefix`` at a fresh
    empty directory before importing the package, so the finding is advisory:
    it tells the user the tree is not clean, it does not mean the bytecode ran.
    Hidden files block -- nothing in the runtime surface is meant to be hidden
    from a directory listing.
    """
    files: list[Path] = []
    findings: list[Finding] = []
    package_install = _is_package_install(root)
    for entry in AUDIT_SURFACE:
        path = root / entry
        if path.is_symlink():
            raise GateError(f"{entry} is a symbolic link")
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for child in sorted(path.rglob("*")):
                relative = child.relative_to(root).as_posix()
                if child.is_symlink():
                    raise GateError(f"{relative} is a symbolic link")
                if "__pycache__" in child.parts or child.suffix.lower() in {".pyc", ".pyo"}:
                    if child.is_file() and not package_install:
                        findings.append(Finding(
                            relative, 0, "bytecode.present",
                            "stray bytecode in the runtime surface (entry points ignore it); delete __pycache__",
                        ))
                    continue
                if child.name.startswith(".") and child.name not in TOLERATED_HIDDEN_FILES:
                    if child.is_file():
                        findings.append(Finding(relative, 0, "self.hidden_file", "is a hidden file in the runtime surface"))
                    continue
                if child.name in TOLERATED_HIDDEN_FILES:
                    continue
                if child.is_file():
                    files.append(child)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix().lower()), findings


def audit_converter(root: Path) -> list[Finding]:
    """Audit the converter checkout or install at ``root``.

    Raises :class:`GateError` when a file cannot be read or parsed, because an
    unreadable surface is an unknown result, not a pass.
    """
    root = root.expanduser().resolve()
    if not (root / "book_to_skill").is_dir():
        raise GateError(f"{root} does not contain the book_to_skill package")
    files, findings = _walk_surface(root)
    for path in files:
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if size > MAX_SOURCE_FILE_BYTES:
            findings.append(Finding(relative, 0, "self.oversized_file", f"is {size:,} bytes; converter sources are small"))
            continue
        suffix = path.suffix.lower()
        if suffix in SUSPICIOUS_EXTENSIONS:
            findings.append(Finding(relative, 0, "self.binary_or_script_file", "is a binary, archive or shell-script file in the runtime surface"))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(relative, 0, "self.not_utf8", "is not valid UTF-8 text"))
            continue
        except OSError as exc:
            raise GateError(f"could not read {relative}") from exc
        if suffix == ".py":
            findings.extend(_audit_python(relative, text))
        elif suffix in {".md", ".txt", ".json", ".toml", ".cfg", ".ini", ".yml", ".yaml"}:
            findings.extend(_audit_markdown(relative, text))
        else:
            findings.append(Finding(relative, 0, "self.unexpected_file_type", f"has an unexpected extension {suffix or '(none)'}"))
    return sorted(findings, key=_finding_key)


def converter_root() -> Path:
    return Path(__file__).resolve().parent.parent
