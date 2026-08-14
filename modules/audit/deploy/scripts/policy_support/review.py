"""Guide an administrator through review of an exact audit bundle."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from .bundle import POLICY_FILES, fail
from .terminal import Action, Terminal

STAGE_COUNT = 6
STAGE_SEPARATOR = "=" * 78
NAVIGATION_PROMPT = (
    "Next: Enter/Space, n, Vim, arrows | Back: b/p | Quit: q/Esc"
)
APPROVAL_PROMPT = (
    "Digest entry: Enter/Space, n, Vim, arrows | Back: b/p | Quit: q/Esc"
)
DIGEST_PROMPT = (
    "Type the complete bundle SHA-256, then press Enter.\n"
    "Ctrl-C: return to Stage 6 navigation | Ctrl-D: abort review\n"
    "Digest: "
)


def stage_screen(number: int, title: str, lines: list[str]) -> str:
    content = [
        STAGE_SEPARATOR,
        f"STAGE {number} OF {STAGE_COUNT}: {title}",
        STAGE_SEPARATOR,
        "",
        *lines,
    ]
    return "\n".join(content)


def review_paths(
    entries: list[dict[str, str]],
) -> tuple[list[Path], list[Path], list[Path]]:
    files = [item for item in entries if item["kind"] == "file"]
    policy_sources = sorted(
        [Path(policy_name) for policy_name, _ in POLICY_FILES.values()]
        + [Path("schema") / schema_name for _, schema_name in POLICY_FILES.values()])
    runtime_sources = sorted({Path(item["source"])
                              for item in files if "source" in item})
    generated_outputs = [Path("artifact-index.json")] + [
        Path(item["bundle_path"]) for item in files if "generated" in item]
    return policy_sources, runtime_sources, generated_outputs


def path_lines(label: str, root: Path, paths: list[Path]) -> list[str]:
    return [f"{label} root:", f"  {root}", "", *[f"- {path}" for path in paths]]


def validation_screen(entries: list[dict[str, str]]) -> str:
    directories = [item for item in entries if item["kind"] == "directory"]
    files = [item for item in entries if item["kind"] == "file"]
    generated = [item for item in files if "generated" in item]
    copied = [item for item in files if "source" in item]
    lines = [
        "Automated integrity validation: PASSED",
        "",
        "The deterministic checks verified:",
        "- policy structure and security invariants;",
        "- the reconstructed artifact tree and index;",
        "- copied and generated file provenance; and",
        "- Python, shell, and sudoers syntax.",
        "",
        "BUNDLE SUMMARY",
        f"Directories: {len(directories)}",
        f"Copied files: {len(copied)}",
        f"Generated files: {len(generated)}",
        f"Total files: {len(files)}",
        "",
        "Navigation is informational and is not retained as approval.",
    ]
    return stage_screen(1, "AUTOMATED VALIDATION", lines)


def policy_screen(policy_dir: Path, paths: list[Path]) -> str:
    lines = [
        "Open every file and confirm that the policy and validation constraints",
        "express the security behavior you intend.",
        "",
        *path_lines("Policy", policy_dir, paths),
    ]
    return stage_screen(2, "POLICY AND SCHEMA REVIEW", lines)


def runtime_screen(module_dir: Path, paths: list[Path]) -> str:
    lines = [
        "Open every file and decide whether you trust the executable content",
        "that will be copied into the deployment bundle.",
        "",
        *path_lines("Module", module_dir, paths),
    ]
    return stage_screen(3, "RUNTIME SOURCE REVIEW", lines)


def generated_screen(artifacts_dir: Path, paths: list[Path]) -> str:
    lines = [
        "Open every generated file, including the artifact index and policy",
        "manifest, and confirm that the result matches your intent.",
        "",
        *path_lines("Artifact", artifacts_dir, paths),
    ]
    return stage_screen(4, "GENERATED OUTPUT REVIEW", lines)


def installation_screen(entries: list[dict[str, str]]) -> str:
    ownerships = [f"{item['owner']}:{item['group']}" for item in entries]
    owner_width = max([len("OWNER:GROUP"), *(len(owner) for owner in ownerships)])
    header = (
        f"{'KIND':<4}  {'MODE':<4}  "
        f"{'OWNER:GROUP':<{owner_width}}  DESTINATION"
    )
    rows = [
        f"{('DIR' if item['kind'] == 'directory' else 'FILE'):<4}  "
        f"{item['mode']:<4}  {owner:<{owner_width}}  "
        f"{item['destination']}"
        for item, owner in zip(entries, ownerships, strict=True)
    ]
    lines = [
        "Confirm every installation destination, owner, group, and mode.",
        header,
        *rows,
    ]
    return stage_screen(5, "INSTALLATION PLAN REVIEW", lines)


def approval_screen(artifacts_dir: Path, policy_digest: str,
                    bundle_digest: str) -> str:
    lines = [
        "Integrity revalidation: PASSED",
        "",
        "Only the complete digest and final integrity check record approval.",
        "",
        "Optional verification from the artifact root shown below:",
        "  sha256sum -- artifact-index.json",
        "",
        "Artifact root:",
        f"  {artifacts_dir}",
        "Artifact index: artifact-index.json",
        f"Policy SHA-256: {policy_digest}",
        f"Bundle SHA-256: {bundle_digest}",
        "",
        "Use a forward key to enter the approval digest.",
    ]
    return stage_screen(6, "FINAL APPROVAL", lines)


def abort_review() -> None:
    fail("review aborted; no new approval was recorded")


def read_digest() -> str | None:
    try:
        return input(DIGEST_PROMPT).strip()
    except KeyboardInterrupt:
        return None
    except EOFError:
        abort_review()


def run_wizard(policy_dir: Path, module_dir: Path, artifacts_dir: Path,
               index: bytes, policy_digest: str, bundle_digest: str,
               validate_unchanged: Callable[[], None],
               terminal: Terminal | None = None) -> None:
    entries = json.loads(index)["entries"]
    policy_paths, runtime_paths, generated_paths = review_paths(entries)
    screens = [
        validation_screen(entries),
        policy_screen(policy_dir, policy_paths),
        runtime_screen(module_dir, runtime_paths),
        generated_screen(artifacts_dir, generated_paths),
        installation_screen(entries),
    ]
    final_screen = approval_screen(artifacts_dir, policy_digest, bundle_digest)
    display = terminal if terminal is not None else Terminal()
    position = 0
    notice = None

    with display.session():
        while True:
            if position < len(screens):
                content = screens[position]
                if notice:
                    content = f"{content}\n\nNotice: {notice}"
                display.display(content, NAVIGATION_PROMPT)
                action = display.read_action()
                notice = None
                if action == Action.QUIT:
                    abort_review()
                if action == Action.BACK:
                    if position == 0:
                        notice = "Already at the first stage."
                    else:
                        position -= 1
                else:
                    position += 1
                continue

            validate_unchanged()
            display.display(final_screen, APPROVAL_PROMPT)
            action = display.read_action()
            if action == Action.QUIT:
                abort_review()
            if action == Action.BACK:
                position -= 1
                continue

            entered = read_digest()
            if entered is None:
                continue
            if entered != bundle_digest:
                fail("bundle digest did not match; no new approval was recorded")
            validate_unchanged()
            return
