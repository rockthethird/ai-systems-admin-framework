#!/usr/bin/env python3
"""Exercise full-screen review navigation and integrity protection."""

from __future__ import annotations

import contextlib
import fcntl
import os
import pty
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
MODULE_DIR = Path(sys.argv[1]).resolve()
SCRIPTS_DIR = MODULE_DIR / "deploy/scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from policy_support.approval import snapshot_changes
from policy_support.review import (
    APPROVAL_PROMPT,
    DIGEST_PROMPT,
    NAVIGATION_PROMPT,
    run_wizard,
)
from policy_support.terminal import (
    ALTERNATE_SCREEN_ENTER,
    ALTERNATE_SCREEN_EXIT,
    CLEAR_SCREEN,
    Action,
    Terminal,
    action_for,
)


class FakeTerminal:
    def __init__(self, actions: list[Action]) -> None:
        self.actions = iter(actions)
        self.displays: list[tuple[str, str]] = []
        self.session_entered = False
        self.session_exited = False

    @contextlib.contextmanager
    def session(self) -> Iterator[None]:
        self.session_entered = True
        try:
            yield
        finally:
            self.session_exited = True

    def display(self, content: str, prompt: str) -> None:
        self.displays.append((content, prompt))

    def read_action(self) -> Action:
        return next(self.actions)


def test_navigation_contract() -> None:
    digest = "a" * 64
    index = b'{"entries": []}\n'
    terminal = FakeTerminal([
        Action.BACK,
        Action.NEXT,
        Action.NEXT,
        Action.BACK,
        Action.NEXT,
        Action.NEXT,
        Action.NEXT,
        Action.NEXT,
        Action.BACK,
        Action.NEXT,
        Action.NEXT,
    ])
    validations = []
    with patch("builtins.input", return_value=digest):
        run_wizard(Path("policy"), Path("module"), Path("artifacts"),
                   index, "b" * 64, digest,
                   lambda: validations.append("validated"), terminal)

    assert terminal.session_entered and terminal.session_exited
    assert validations == ["validated", "validated", "validated"], validations
    assert any("Already at the first stage" in content
               for content, _ in terminal.displays)
    assert sum("STAGE 2 OF 6" in content
               for content, _ in terminal.displays) == 2
    assert sum("STAGE 6 OF 6" in content
               for content, _ in terminal.displays) == 2
    for content, prompt in terminal.displays:
        assert max(map(len, content.splitlines())) <= 80, content
        assert len(content.splitlines()) + 2 <= 24, content
        assert len(prompt) <= 80


def test_digest_interrupt_returns_to_navigation() -> None:
    digest = "a" * 64
    terminal = FakeTerminal([Action.NEXT] * 7)
    validations = []
    with patch("builtins.input", side_effect=[KeyboardInterrupt(), digest]) as reader:
        run_wizard(Path("policy"), Path("module"), Path("artifacts"),
                   b'{"entries": []}\n', "b" * 64, digest,
                   lambda: validations.append("validated"), terminal)

    assert reader.call_count == 2
    assert reader.call_args_list[0].args == (DIGEST_PROMPT,)
    assert "Ctrl-C: return to Stage 6 navigation" in DIGEST_PROMPT
    assert "Ctrl-D: abort review" in DIGEST_PROMPT
    assert "b/p" not in DIGEST_PROMPT and "q + Enter" not in DIGEST_PROMPT
    assert sum("STAGE 6 OF 6" in content
               for content, _ in terminal.displays) == 2
    assert validations == ["validated", "validated", "validated"]


def test_digest_accepts_no_navigation_commands() -> None:
    for entered in ("b", "p", "q"):
        terminal = FakeTerminal([Action.NEXT] * 6)
        with patch("builtins.input", return_value=entered):
            try:
                run_wizard(Path("policy"), Path("module"), Path("artifacts"),
                           b'{"entries": []}\n', "b" * 64, "a" * 64,
                           lambda: None, terminal)
            except ValueError as error:
                assert "bundle digest did not match" in str(error)
            else:
                raise AssertionError(f"digest entry accepted command: {entered}")


def test_key_map() -> None:
    for key in (b"\r", b"\n", b" ", b"n", b"N", b"j", b"J", b"l", b"L",
                b"\x1b[B", b"\x1b[C", b"\x1bOB", b"\x1bOC"):
        assert action_for(key) == Action.NEXT, key
    for key in (b"b", b"B", b"p", b"P", b"h", b"H", b"k", b"K",
                b"\x1b[A", b"\x1b[D", b"\x1bOA", b"\x1bOD"):
        assert action_for(key) == Action.BACK, key
    for key in (b"q", b"Q", b"\x1b", b"\x04"):
        assert action_for(key) == Action.QUIT, key
    assert action_for(b"x") is None


def set_terminal_size(descriptor: int, lines: int = 24,
                      columns: int = 80) -> None:
    size = struct.pack("HHHH", lines, columns, 0, 0)
    fcntl.ioctl(descriptor, termios.TIOCSWINSZ, size)


def read_available(descriptor: int) -> bytes:
    content = bytearray()
    while select.select([descriptor], [], [], 0.05)[0]:
        content.extend(os.read(descriptor, 65536))
    return bytes(content)


def test_terminal_restoration() -> None:
    master, slave = pty.openpty()
    set_terminal_size(slave)
    original = termios.tcgetattr(slave)
    terminal = Terminal(slave, slave)
    try:
        with patch.dict(os.environ, {"TERM": "xterm-256color"}):
            with terminal.session():
                terminal.display("review stage", "navigation prompt")
                os.write(master, b"\x1b[D")
                assert terminal.read_action() == Action.BACK
                assert termios.tcgetattr(slave) == original
                with patch.object(terminal, "read_sequence", return_value=b""):
                    assert terminal.read_action() == Action.QUIT
                assert termios.tcgetattr(slave) == original
                with patch.object(terminal, "read_sequence",
                                  side_effect=KeyboardInterrupt()):
                    assert terminal.read_action() == Action.QUIT
                assert termios.tcgetattr(slave) == original

                try:
                    terminal.validate_screen("x" * 81, "prompt")
                except ValueError as error:
                    assert "requires 81 columns" in str(error)
                else:
                    raise AssertionError("oversized screen was accepted")
                try:
                    terminal.validate_screen("unsafe\x1b[2J", "prompt")
                except ValueError as error:
                    assert "non-printable" in str(error)
                else:
                    raise AssertionError("terminal control injection was accepted")
        assert termios.tcgetattr(slave) == original
        output = read_available(master)
        assert ALTERNATE_SCREEN_ENTER.encode() in output
        assert CLEAR_SCREEN.encode() in output
        assert b"review stage\r\n\r\nnavigation prompt" in output
        assert ALTERNATE_SCREEN_EXIT.encode() in output
    finally:
        os.close(master)
        os.close(slave)


def test_change_classification() -> None:
    before = {
        "policy/removed.yaml": ("file", 0o600, "old"),
        "runtime/changed.py": ("file", 0o700, "old"),
    }
    after = {
        "runtime/changed.py": ("file", 0o700, "new"),
        "artifacts/added.json": ("file", 0o600, "new"),
    }
    assert snapshot_changes(before, after) == [
        ("REMOVED", "policy/removed.yaml"),
        ("ADDED", "artifacts/added.json"),
        ("MODIFIED", "runtime/changed.py"),
    ]


class Transcript:
    def __init__(self, process: subprocess.Popen[bytes], terminal: int) -> None:
        self.process = process
        self.terminal = terminal
        self.content = bytearray()
        self.cursor = 0

    def expect(self, expected: str) -> None:
        deadline = time.monotonic() + 15
        marker = expected.encode()
        while True:
            position = self.content.find(marker, self.cursor)
            if position >= 0:
                self.cursor = position + len(marker)
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.process.kill()
                raise AssertionError(f"review output not received: {expected}")
            ready, _, _ = select.select([self.terminal], [], [], remaining)
            if ready:
                self.content.extend(os.read(self.terminal, 65536))

    def finish(self) -> str:
        deadline = time.monotonic() + 15
        try:
            while self.process.poll() is None:
                if time.monotonic() >= deadline:
                    self.process.kill()
                    raise AssertionError("review did not terminate")
                ready, _, _ = select.select([self.terminal], [], [], 1)
                if ready:
                    self.content.extend(os.read(self.terminal, 65536))
        except OSError:
            pass
        finally:
            os.close(self.terminal)
        self.process.wait(timeout=5)
        return self.content.decode(errors="replace").replace("\r", "")


def start_review(
    root: Path, *, controlling_terminal: bool = False,
) -> tuple[subprocess.Popen[bytes], Transcript, Path, Path, Path]:
    policy = root / "policy"
    artifacts = root / "artifacts"
    state = root / "state"
    shutil.copytree(MODULE_DIR / "deploy/policy", policy)
    master, slave = pty.openpty()
    set_terminal_size(slave)
    environment = {**os.environ, "TERM": "xterm-256color"}

    def claim_terminal() -> None:
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        [sys.executable, str(SCRIPTS_DIR / "policy.py"), "review",
         "--policy-dir", str(policy), "--artifacts-dir", str(artifacts),
         "--state-dir", str(state)],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
        env=environment,
        preexec_fn=claim_terminal if controlling_terminal else None,
    )
    os.close(slave)
    return process, Transcript(process, master), policy, artifacts, state


def test_signal_restoration() -> None:
    master, slave = pty.openpty()
    set_terminal_size(slave)
    environment = {**os.environ, "TERM": "xterm-256color"}
    program = f"""
import signal
import sys
sys.path.insert(0, {str(SCRIPTS_DIR)!r})
from policy_support.terminal import Terminal
terminal = Terminal()
with terminal.session():
    terminal.write("READY")
    signal.pause()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", program],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
        env=environment,
    )
    os.close(slave)
    transcript = Transcript(process, master)
    transcript.expect("READY")
    process.terminate()
    output = transcript.finish()
    assert process.returncode == 143, output
    assert ALTERNATE_SCREEN_ENTER in output
    assert ALTERNATE_SCREEN_EXIT in output


def test_digest_interrupt_in_terminal() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        process, transcript, _, _, state = start_review(
            Path(temporary), controlling_terminal=True)

        for stage in range(1, 6):
            transcript.expect(f"STAGE {stage} OF 6")
            transcript.expect(NAVIGATION_PROMPT)
            os.write(transcript.terminal, b"l")
        transcript.expect("STAGE 6 OF 6: FINAL APPROVAL")
        transcript.expect(APPROVAL_PROMPT)
        os.write(transcript.terminal, b"l")
        transcript.expect("Ctrl-C: return to Stage 6 navigation")
        os.write(transcript.terminal, b"\x03")
        transcript.expect("STAGE 6 OF 6: FINAL APPROVAL")
        transcript.expect(APPROVAL_PROMPT)
        os.write(transcript.terminal, b"b")
        transcript.expect("STAGE 5 OF 6: INSTALLATION PLAN REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"q")

        output = transcript.finish()
        assert process.returncode != 0, output
        assert "review aborted; no new approval was recorded" in output
        assert not (state / "policy-approval.json").exists()


def test_mid_review_mutation() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        process, transcript, policy, _, state = start_review(Path(temporary))

        transcript.expect("STAGE 1 OF 6: AUTOMATED VALIDATION")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"l")
        transcript.expect("STAGE 2 OF 6: POLICY AND SCHEMA REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"j")
        transcript.expect("STAGE 3 OF 6: RUNTIME SOURCE REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"k")
        transcript.expect("STAGE 2 OF 6: POLICY AND SCHEMA REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"\x1b[C")
        transcript.expect("STAGE 3 OF 6: RUNTIME SOURCE REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"\x1b[B")
        transcript.expect("STAGE 4 OF 6: GENERATED OUTPUT REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        os.write(transcript.terminal, b"n")
        transcript.expect("STAGE 5 OF 6: INSTALLATION PLAN REVIEW")
        transcript.expect(NAVIGATION_PROMPT)
        identity_policy = policy / "identities.yaml"
        identity_policy.write_text(
            identity_policy.read_text() + "\n# changed during review\n")
        os.write(transcript.terminal, b" ")

        output = transcript.finish()
        assert process.returncode != 0, output
        assert "reviewed bundle changed during review" in output, output
        assert "MODIFIED: policy/identities.yaml" in output, output
        assert "The previous review is no longer valid. Restart the review." in output
        assert "STAGE 6 OF 6: FINAL APPROVAL" not in output, output
        assert ALTERNATE_SCREEN_ENTER in output
        exit_position = output.find(ALTERNATE_SCREEN_EXIT)
        error_position = output.find("reviewed bundle changed during review")
        assert 0 <= exit_position < error_position, output
        assert not (state / "policy-approval.json").exists()


def main() -> None:
    test_navigation_contract()
    test_digest_accepts_no_navigation_commands()
    test_key_map()
    test_terminal_restoration()
    test_change_classification()
    test_signal_restoration()
    test_digest_interrupt_in_terminal()
    test_mid_review_mutation()
    print("policy review wizard tests passed")


if __name__ == "__main__":
    main()
