---
description: "How book-to-skill is built: a deterministic Python extractor plus a spec-driven agent generator. Pipeline, component map, and the design tradeoffs behind both."
seo_title: "Architecture - How book-to-skill Extracts and Generates"
---

# Architecture

book-to-skill has two halves: a **deterministic extractor** (Python) and a
**spec-driven generator** (the agent following `SKILL.md`). The extractor turns any
document into clean text + metadata; the agent turns that into a structured skill.

```
            ┌─────────────────────────── EXTRACTOR (Python, deterministic) ──┐
 documents  │  scripts/extract.py (shim)  →  book_to_skill/                   │
 (pdf/epub/ │    ├─ cli.py · utils.py   CLI parse · multi-source · runner     │
  docx/...) │    ├─ config.py           supported extensions · paths · deps   │
     │      │    ├─ dependencies.py     optional-dep probing · --check report │
     ▼      │    ├─ sanitize.py         strip invisible/zero-width Unicode    │
 ───────────│    └─ parsers/            pdf · epub · docx · html · rtf ·      │
            │                             calibre · text (best tool, fallback)│
            │  output → <tempdir>/book_skill_work/                            │
            │    full_text.txt   (all sources merged, source-marked)          │
            │    metadata.json   (pages, words, tokens, chapters, ToC)        │
            │    pdf_pages.json  (optional, physical-page text evidence)       │
            └────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
            ┌─────────────────────────── GENERATOR (agent, follows SKILL.md) ┐
            │  Step 1.5  ask content type → BOOK_TYPE (technical | text)      │
            │  Step 2/2.5 extract · cost estimate · confirm                   │
            │  Step 2.6  REPL-style probing for large books (grep/sed, no     │
            │            full re-reads)                                        │
            │  Step 3    analyze structure (title, author, chapters, ToC)     │
            │  Step 4    purpose → DEPTH (reference | study)                   │
            │  Step 7    per-chapter summaries (budget = BOOK_TYPE × DEPTH)    │
            │  Step 8    glossary · patterns · cheatsheet (decision layer)    │
            │  Step 9/9.5 SKILL.md core + indexes                             │
            └────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
                 <SKILLS_HOME>/<slug>/  ← chosen per host + scope:
                  ~/.copilot/skills/   GitHub Copilot CLI (personal)
                  ~/.agents/skills/    Copilot CLI or Amp (cross-agent, personal)
                  ~/.claude/skills/    Claude Code (personal)
                  ~/.openclaw/skills/  OpenClaw (personal, default state only)
                  $HERMES_HOME/skills/<category>/  Hermes Agent (personal)
                  .github/skills/ | .claude/skills/ | .agents/skills/  project-local (any host)
                  .hermes/skills/<category>/                         Hermes project-local
                  skills/                                                   OpenClaw workspace
                  ~/.config/opencode/skills/                         OpenCode (own root; on request)
                  .opencode/skills/                                  OpenCode project-local
                  scope: personal vs project-local (Step 5, BOOK_TO_SKILL_SCOPE)
                  SKILL.md         core frameworks + chapter & topic index (~4K)
                  chapters/*.md    on-demand, loaded only when asked
                  glossary.md      terms
                  patterns.md      techniques
                  cheatsheet.md    decision rules / trees / trade-offs / tells
```

OpenClaw's shared `~/.agents/skills` compatibility root is discoverable only
when `OPENCLAW_STATE_DIR` is unset or uses the default `~/.openclaw`. A
non-default state uses its active `<state-dir>/skills` root instead; the
converter does not infer arbitrary `skills.load.extraDirs`.

## Design principles

1. **Extract structure, not summaries** — named frameworks, decision rules,
   anti-patterns; never raw passages.
2. **Compile-time over runtime** — pay navigation/structuring once; at query time
   load only the relevant chapter. See [Performance & Cost](performance.md).
3. **On-demand chapters** — `SKILL.md` stays small; chapter files cost tokens only
   when read.
4. **Front-loaded `SKILL.md`** — most important content first (compaction truncates
   from the end).
5. **Graceful degradation** — every format has a stdlib fallback; one bad source is
   skipped, not fatal.

## Key components

| Path | Responsibility |
|------|----------------|
| `scripts/extract.py` | thin entrypoint shim → `book_to_skill.cli` (kept so old invocations keep working) |
| `book_to_skill/cli.py`, `utils.py` | CLI parsing, multi-source resolution, chapter/ToC detection, runner |
| `book_to_skill/parsers/` | one module per format (`pdf`, `epub`, `docx`, `html`, `rtf`, `calibre`, `text`) |
| `book_to_skill/config.py` | supported extensions, output paths, dependency map |
| `book_to_skill/dependencies.py` | optional-dependency probing + `--check` |
| `book_to_skill/sanitize.py` | strips zero-width / Unicode-tag-block characters from extracted text, and folds Kangxi radicals to their ideographs (see Security) |
| `tools/discovery_tax.py` | measures token cost vs context-dump / discovery loop |
| `tools/validate_skill.py` | checks a generated SKILL.md against host rules (`--lens claude\|copilot\|amp\|hermes\|openclaw\|opencode`) |
| `book_to_skill/safety_gate.py` | rule tables, extracted-text classifier and converter self-audit; the extractor calls both (see Security) |
| `tools/safety_gate.py` | gate CLI: `self` / `extracted <workdir>` / `generated <skill-dir>`, exit 0 pass · 1 block · 2 incomplete |
| `tools/scan_generated_skill.py` | advisory prompt-injection scan of a generated skill; rules imported from `safety_gate` (see Security) |
| `SKILL.md` | the generator spec (Steps 0–10 + fold-in workflow) |

## Security

For page-level PDF evidence, run
`python3 scripts/extract.py book.pdf --pdf-page-sidecar`. It additionally
writes `pdf_pages.json` in the workdir.
This opt-in sidecar uses pypdf's text layer even when the main extractor is
different. Each record carries the source SHA-256, one-based physical page,
sanitized text, extraction method, and low-confidence reasons. It does not
change `full_text.txt` or `metadata.json`, and it provides no exact character
offsets into the cleaned full text. A suspected merged decimal token (for
example `0.2070.110`) remains untouched and is marked for manual PDF-table
review; the code does not infer column separators. If pypdf cannot read the
source or the source hash changes, the sidecar marks that source unavailable
instead of inventing page evidence.

Untrusted documents flow into an agent's context and then into a generated skill
that later loads into other agents — a document→context supply chain. The hardening
is layered:

- **Extraction sanitization** (`book_to_skill/sanitize.py`) — strips zero-width
  (`U+200B/200C/200D/2060/FEFF`) and the Unicode tag block (`U+E0000–E007F`) from
  every parser's output before metrics or `full_text.txt`, so invisible
  document-borne instructions never reach the agent. Reports the removal count;
  rejects a source with no visible content left.
- **CJK radical folding** (`book_to_skill/sanitize.py`) — PDFs whose embedded
  font subset carries no correct Unicode mapping emit a Kangxi radical
  (`U+2F00–U+2FDF`) where a character belongs, so a Chinese book extracts
  "判断⼒" for "判断力". Each radical in that block has a Unicode compatibility
  decomposition, so the fold is NFKC applied to those code points only: the rest
  of the text is passed through byte for byte. Nothing is removed, so it does
  not count toward the security removal total. CJK Radicals Supplement
  (`U+2E80–U+2EF3`) is deliberately not folded — Unicode defines no
  decomposition for it, and some entries are ordinary kanji.
- **DOCX XXE / Billion-Laughs guard** (`parsers/docx.py`) — rejects any XML part
  declaring a DTD or entities before parsing.
- **Subprocess argument-injection** — file paths are absolutised before reaching
  `pdftotext` / `pdfinfo` / `ebook-convert`, so a `-`-leading filename can't be read
  as a flag.
- **Generated-skill scan** (`tools/scan_generated_skill.py`) — an advisory step in
  the generator (Step 9.5) that flags instruction-override phrases, model-control
  tags, residual invisible Unicode, authority-widening frontmatter, and
  exfiltration-shaped content across the generated `SKILL.md`, `chapters/*.md`,
  `glossary.md`, `patterns.md`, and `cheatsheet.md`. Findings name only the rule and
  file location — never the matched text.
- **Safety gate** (`book_to_skill/safety_gate.py`, `tools/safety_gate.py`) — the
  deterministic, blocking layer the extractor cannot skip. Three subjects:
  - *converter self-audit* — runs at every extractor start and in CI. Parses the
    runtime surface (`book_to_skill/`, `scripts/`, `tools/`, `SKILL.md`) with
    `ast` and blocks on network/IPC imports, `eval`/`exec`/dynamic import,
    payload decoders (`base64`, `zlib`, `fromhex`, hex-escape runs, opaque blobs),
    `subprocess` with `shell=True` or a command outside the allowlist
    (`pdftotext`, `pdfinfo`, `ebook-convert`, `git`, `python -m pip`), secret-shaped
    environment reads, wallet/browser/credential path literals, URLs outside the
    documented hosts, raw `IP:port` literals, bidi controls in source, any
    binary, archive, hidden, shell-script or sourceless `.pyc` file. Stray
    `__pycache__` bytecode is reported as advisory; the entry points set `sys.pycache_prefix` to a
    fresh empty directory before importing, so a planted `.pyc` beside a clean
    source is never loaded. Exit code 4 from the extractor; nothing is
    opened or installed first.
  - *extracted text* — classified before `full_text.txt` is written. Blocking
    rules: residual invisible Unicode, chat-template / system / tool-call tokens,
    download-and-execute pipelines, decode-and-run shapes, base64 data URIs,
    secret-bearing query strings, exfiltration language. Prose-shaped phrases
    (instruction override, role reassignment, concealment from the user, text
    addressed to an AI) are advisory. On block the text goes to
    `quarantined_text.txt`, `safety.json` records the findings, no
    `metadata.json` is written, and the extractor exits 3. `--safety-override`
    writes normally and records the override in both files.
  - *generated skill* — the Step 9.5 gate; same rules over the scanner's bounded
    file set, with the same block/advisory split.
  The scope is static shapes. It does not catch a hostile fork that also removes
  the gate; verifying the install source (SECURITY-NOTICE.md) remains the
  out-of-band control for that.
- **CI** — CodeQL, Bandit (gate on HIGH), safety-gate self-audit (hard gate),
  Zizmor, and dependency CVE review on PRs.

## Extending

- **New format** → add `book_to_skill/parsers/<fmt>.py`, register its extension in
  `config.py`, wire dependency probing in `dependencies.py`, branch in
  `utils.extract_single_file`.
- **New generation behavior** → edit the relevant Step in `SKILL.md`; keep it lean
  and back the change with evidence (see CONTRIBUTING.md).
