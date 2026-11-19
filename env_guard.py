#!/usr/bin/env python3
"""Check staged changes for missing environment variables and exposed secrets."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SAFE_ENV_FILES = {".env.example", ".env.sample", ".env.template", ".env.dist"}
# Files whose environment variable usages are compared with .env.example.
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
# Programming languages: only quoted literals count as hard-coded secrets there,
# so that `password = request.form["password"]` is not reported.
CODE_SUFFIXES = SOURCE_SUFFIXES | {
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs", ".swift",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".scala", ".dart", ".vue", ".svelte",
}
MAX_FILE_SIZE = 1_000_000
HOOK_MARKER = "# installed by env-guard"

VARIABLE_PATTERNS = (
    re.compile(r"os\.getenv\(\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1"),
    re.compile(r"os\.environ\.get\(\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1"),
    re.compile(r"os\.environ\[\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1\s*\]"),
    re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"process\.env\[\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1\s*\]"),
    re.compile(r"import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
)

# A sensitive name may carry a prefix (DB_PASSWORD, dbPassword) or a suffix
# separated by _ or - (SECRET_KEY, github-token), but "tokenizer" is not one.
SENSITIVE_KEYWORDS = (
    r"password|passwd|pwd|secret[_-]?key|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|client[_-]?secret|auth[_-]?key"
)
ASSIGNMENT_SECRET = re.compile(
    r"[A-Za-z0-9_-]*?(?:" + SENSITIVE_KEYWORDS + r")(?:[_-][A-Za-z0-9]+)*"
    r"[\"']?\s*(?::=|=|:)(?![=>])\s*"
    r"(?:[\"'](?P<quoted>[^\"']*)[\"']|(?P<bare>[^\s,;#\[{(][^\s,;#]*))",
    re.IGNORECASE,
)
KNOWN_SECRET_PATTERNS = (
    ("clé privée", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("clé d'accès AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jeton GitHub", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("clé secrète Stripe", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("clé API Google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jeton Slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("clé API Anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("clé API OpenAI", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}")),
    ("URL avec mot de passe", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@\"']+:[^\s@/\"'$<{]{3,}@[^\s\"']+", re.IGNORECASE)),
)
PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change-me",
    "change_me",
    "dummy",
    "example",
    "fake",
    "none",
    "null",
    "placeholder",
    "redacted",
    "replace-me",
    "replace_me",
    "test",
    "todo",
    "true",
    "false",
}
ENV_REFERENCE = re.compile(
    r"^(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|process\.env(?:\.|\[)|import\.meta\.env\.|os\.getenv\(|os\.environ)"
)


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int | None
    message: str


class EnvGuardError(Exception):
    """An expected, user-facing configuration or Git error."""


def git(root: Path, *args: str, check: bool = True) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise EnvGuardError(detail or "La commande Git a échoué.")
    return result.stdout


def git_paths(root: Path, *args: str) -> list[str]:
    output = git(root, *args)
    return [part.decode("utf-8", errors="surrogateescape") for part in output.split(b"\0") if part]


def load_config(root: Path) -> dict:
    path = root / ".env-guard.json"
    if not path.exists():
        return {"ignore_paths": [], "allowed_env_files": [], "secret_allowlist": []}
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EnvGuardError(f"Configuration invalide dans {path.name}: {error}") from error
    if not isinstance(config, dict):
        raise EnvGuardError(f"{path.name} doit contenir un objet JSON.")

    for key in ("ignore_paths", "allowed_env_files", "secret_allowlist"):
        if key in config and not isinstance(config[key], list):
            raise EnvGuardError(f"La propriété {key!r} de {path.name} doit être une liste.")
    for key in ("ignore_paths", "allowed_env_files"):
        if any(not isinstance(item, str) or not item.strip() for item in config.get(key, [])):
            raise EnvGuardError(f"Chaque élément de {key!r} dans {path.name} doit être un texte non vide.")
    for entry in config.get("secret_allowlist", []):
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(key), str) and entry[key].strip()
            for key in ("path", "pattern", "reason")
        ):
            raise EnvGuardError(
                "Chaque exception de secret doit contenir path, pattern et reason."
            )
        try:
            re.compile(entry["pattern"])
        except re.error as error:
            raise EnvGuardError(f"Expression régulière invalide dans la liste d'exceptions: {error}") from error
    return config


def matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def ignored(path: str, config: dict) -> bool:
    return matches_any(path, config.get("ignore_paths", []))


def is_env_file(path: str, config: dict) -> bool:
    basename = Path(path).name
    allowed = SAFE_ENV_FILES | set(config.get("allowed_env_files", []))
    looks_like_env = basename == ".env" or basename.startswith(".env.")
    return looks_like_env and basename not in allowed and not matches_any(path, allowed)


def parse_env_names(content: str) -> set[str]:
    names = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if match:
            names.add(match.group(1))
    return names


def used_variables(lines: Iterable[tuple[int, str]]) -> dict[str, int]:
    found: dict[str, int] = {}
    for line_number, line in lines:
        for pattern in VARIABLE_PATTERNS:
            for match in pattern.finditer(line):
                name = match.group(2) if len(match.groups()) > 1 else match.group(1)
                found.setdefault(name, line_number)
    return found


def is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        lowered in PLACEHOLDER_VALUES
        or (lowered.startswith("<") and lowered.endswith(">"))
        or lowered.startswith(("your_", "your-", "my_", "my-"))
        or set(lowered) <= {"x", "*", ".", "-"}
        or bool(ENV_REFERENCE.match(value.strip()))
    )


def secret_type(line: str, path: str = "") -> str | None:
    for label, pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(line):
            return label
    in_code = Path(path).suffix.lower() in CODE_SUFFIXES
    for match in ASSIGNMENT_SECRET.finditer(line):
        value = match.group("quoted")
        if value is None:
            # In code, a bare value is an expression (a call, a variable...),
            # not a hard-coded secret. In config files it is the value itself.
            if in_code:
                continue
            value = match.group("bare")
        if not is_placeholder(value):
            return "valeur affectée à une variable sensible"
    return None


def staged_added_lines(root: Path, path: str) -> list[tuple[int, str]]:
    patch = git(root, "diff", "--cached", "--no-ext-diff", "--unified=0", "--no-renames", "--", path)
    lines: list[tuple[int, str]] = []
    current_line: int | None = None
    for raw_line in patch.decode("utf-8", errors="replace").splitlines():
        if raw_line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,\d+)?", raw_line)
            current_line = int(match.group(1)) if match else None
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            if current_line is not None:
                lines.append((current_line, raw_line[1:]))
                current_line += 1
        elif raw_line.startswith(" ") and current_line is not None:
            current_line += 1
    return lines


def staged_file_content(root: Path, path: str) -> str | None:
    staged_entry = git(root, "ls-files", "--stage", "--", path, check=False)
    if not staged_entry:
        return None
    result = git(root, "show", f":0:{path}")
    return result.decode("utf-8-sig", errors="replace")


def working_file_content(root: Path, path: str) -> str | None:
    """Return the text of a working-tree file, or None if absent, binary or too large."""
    file_path = root / path
    try:
        if not file_path.is_file() or file_path.stat().st_size > MAX_FILE_SIZE:
            return None
        data = file_path.read_bytes()
    except OSError as error:
        raise EnvGuardError(f"Impossible de lire {path}: {error}") from error
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8-sig", errors="replace")


def allowed_secret(path: str, line: str, config: dict) -> bool:
    for entry in config.get("secret_allowlist", []):
        if fnmatch.fnmatchcase(path, entry["path"]) and re.search(entry["pattern"], line):
            return True
    return False


def check_repository(root: Path, scan_all: bool) -> list[Finding]:
    config = load_config(root)
    findings: list[Finding] = []

    for path in git_paths(root, "ls-files", "--cached", "-z"):
        if not ignored(path, config) and is_env_file(path, config):
            findings.append(
                Finding(
                    "tracked-env-file",
                    path,
                    None,
                    "Fichier .env suivi par Git : retirez-le avec `git rm --cached` et ajoutez-le à .gitignore.",
                )
            )
    for path in git_paths(root, "ls-files", "--others", "--exclude-standard", "-z"):
        if not ignored(path, config) and is_env_file(path, config):
            findings.append(
                Finding(
                    "unignored-env-file",
                    path,
                    None,
                    "Fichier .env non ignoré : ajoutez-le à .gitignore avant qu'il ne soit commité.",
                )
            )

    candidate_lines: dict[str, list[tuple[int, str]]] = {}
    if scan_all:
        for path in git_paths(root, "ls-files", "-co", "--exclude-standard", "-z"):
            if ignored(path, config):
                continue
            content = working_file_content(root, path)
            if content is not None:
                candidate_lines[path] = list(enumerate(content.splitlines(), start=1))
    else:
        staged = git_paths(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
        for path in staged:
            if not ignored(path, config):
                candidate_lines[path] = staged_added_lines(root, path)

    source_uses: dict[str, dict[str, int]] = {}
    for path, lines in candidate_lines.items():
        if Path(path).suffix.lower() in SOURCE_SUFFIXES:
            source_uses[path] = used_variables(lines)

        for line_number, line in lines:
            label = secret_type(line, path)
            if label and not allowed_secret(path, line, config):
                findings.append(
                    Finding("possible-secret", path, line_number, f"Secret potentiel détecté : {label}.")
                )

    all_uses: dict[str, tuple[str, int]] = {}
    for path, names in source_uses.items():
        for name, line_number in names.items():
            all_uses.setdefault(name, (path, line_number))

    if all_uses:
        env_example = ".env.example"
        if scan_all:
            example_content = working_file_content(root, env_example)
        else:
            example_content = staged_file_content(root, env_example)
        if example_content is None:
            findings.append(
                Finding(
                    "missing-env-example",
                    env_example,
                    None,
                    "Impossible de vérifier les variables : fichier .env.example absent.",
                )
            )
        else:
            declared = parse_env_names(example_content)
            for name, (path, line_number) in sorted(all_uses.items()):
                if name not in declared:
                    findings.append(
                        Finding(
                            "missing-variable",
                            path,
                            line_number,
                            f"Variable {name} absente de .env.example.",
                        )
                    )

    return findings


def install_hook(root: Path, force: bool) -> Path:
    hooks_dir = Path(git(root, "rev-parse", "--git-path", "hooks").decode().strip())
    if not hooks_dir.is_absolute():
        hooks_dir = root / hooks_dir
    hook = hooks_dir / "pre-commit"
    if hook.exists() and HOOK_MARKER not in hook.read_text(encoding="utf-8", errors="replace") and not force:
        raise EnvGuardError(
            f"Un hook pre-commit existe déjà ({hook}). Relancez avec --force pour le remplacer."
        )
    python = Path(sys.executable).as_posix()
    script = Path(__file__).resolve().as_posix()
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(
        "#!/bin/sh\n"
        f"{HOOK_MARKER}\n"
        f'exec "{python}" "{script}" --root "$(git rev-parse --show-toplevel)"\n',
        encoding="utf-8",
        newline="\n",
    )
    hook.chmod(0o755)
    return hook


def display(findings: list[Finding]) -> None:
    if not findings:
        print("Env Guard : aucune erreur détectée.")
        return
    print(f"Env Guard : vérification échouée ({len(findings)} problème(s))\n")
    for finding in findings:
        location = finding.path
        if finding.line is not None:
            location += f":{finding.line}"
        print(f"ERREUR  {finding.message}\n        {location}")
    print(
        "\nCorrigez ces problèmes, ou ajoutez une exception justifiée dans .env-guard.json."
        "\nSi un vrai secret a déjà été commité ou poussé, considérez-le comme compromis et révoquez-le."
    )


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Vérifie les variables d'environnement et les secrets avant un commit."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Analyser les fichiers du dépôt (suivis et non ignorés), pas seulement les changements indexés.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Répertoire du dépôt Git (par défaut : répertoire courant).",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Installer Env Guard comme hook Git pre-commit dans le dépôt.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Avec --install-hook : remplacer un hook pre-commit existant.",
    )
    args = parser.parse_args(argv)
    try:
        root = Path(git(args.root.resolve(), "rev-parse", "--show-toplevel").decode().strip())
        if args.install_hook:
            hook = install_hook(root, args.force)
            print(f"Env Guard : hook pre-commit installé ({hook}).")
            return 0
        findings = check_repository(root, args.all)
    except (EnvGuardError, OSError) as error:
        print(f"Env Guard : {error}", file=sys.stderr)
        return 2
    display(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
