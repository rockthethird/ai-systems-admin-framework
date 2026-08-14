"""Provide minimal POSIX terminal controls for the audit review wizard."""

from __future__ import annotations

import os
import select
import signal
import sys
import termios
import time
import tty
from contextlib import contextmanager
from enum import Enum
from typing import Iterator

from .bundle import fail

ALTERNATE_SCREEN_ENTER = "\x1b[?1049h"
ALTERNATE_SCREEN_EXIT = "\x1b[?1049l"
CLEAR_SCREEN = "\x1b[H\x1b[2J"
ERASE_PROMPT = "\r\x1b[2K"
ESCAPE = b"\x1b"
ESCAPE_SEQUENCE_TIMEOUT_SECONDS = 0.1
MINIMUM_COLUMNS = 80
MINIMUM_LINES = 24


class Action(Enum):
    NEXT = "next"
    BACK = "back"
    QUIT = "quit"


SEQUENCE_ACTIONS = {
    b"\x1b[A": Action.BACK,
    b"\x1b[B": Action.NEXT,
    b"\x1b[C": Action.NEXT,
    b"\x1b[D": Action.BACK,
    b"\x1bOA": Action.BACK,
    b"\x1bOB": Action.NEXT,
    b"\x1bOC": Action.NEXT,
    b"\x1bOD": Action.BACK,
}
NEXT_KEYS = {b"\r", b"\n", b" ", b"n", b"j", b"l"}
BACK_KEYS = {b"b", b"p", b"h", b"k"}
QUIT_KEYS = {b"q", b"\x04"}


def action_for(sequence: bytes) -> Action | None:
    if sequence in SEQUENCE_ACTIONS:
        return SEQUENCE_ACTIONS[sequence]
    key = sequence.lower()
    if key in NEXT_KEYS:
        return Action.NEXT
    if key in BACK_KEYS:
        return Action.BACK
    if key in QUIT_KEYS or sequence == ESCAPE:
        return Action.QUIT
    return None


class Terminal:
    """Own terminal display and immediate-key input for one review session."""

    def __init__(self, input_fd: int | None = None,
                 output_fd: int | None = None) -> None:
        self.input_fd = sys.stdin.fileno() if input_fd is None else input_fd
        self.output_fd = sys.stdout.fileno() if output_fd is None else output_fd

    def write(self, value: str) -> None:
        content = value.encode("utf-8")
        while content:
            written = os.write(self.output_fd, content)
            if written == 0:
                raise OSError("terminal output closed while writing")
            content = content[written:]

    def validate(self) -> None:
        if not os.isatty(self.input_fd) or not os.isatty(self.output_fd):
            fail("review requires an interactive terminal on stdin and stdout")
        if os.environ.get("TERM", "").casefold() in {"", "dumb"}:
            fail("review requires a terminal that supports an alternate screen")
        size = os.get_terminal_size(self.output_fd)
        if size.columns < MINIMUM_COLUMNS or size.lines < MINIMUM_LINES:
            fail(
                f"review requires at least {MINIMUM_COLUMNS} columns by "
                f"{MINIMUM_LINES} lines; terminal is {size.columns} by {size.lines}"
            )

    def validate_screen(self, content: str, prompt: str) -> None:
        self.validate()
        if any(character != "\n" and not character.isprintable()
               for character in content + prompt):
            fail("review display contains a non-printable character")
        size = os.get_terminal_size(self.output_fd)
        lines = content.splitlines()
        required_columns = max([len(prompt), *(len(line) for line in lines)], default=0)
        required_lines = len(lines) + 2
        if required_columns > size.columns or required_lines > size.lines:
            fail(
                f"review stage requires {required_columns} columns by "
                f"{required_lines} lines; terminal is {size.columns} by {size.lines}"
            )

    @contextmanager
    def session(self) -> Iterator[None]:
        self.validate()
        previous_handlers = {}

        def terminate(signum: int, _frame: object) -> None:
            raise SystemExit(128 + signum)

        entered = False
        try:
            for signum in (signal.SIGHUP, signal.SIGTERM):
                previous = signal.getsignal(signum)
                if previous != signal.SIG_IGN:
                    previous_handlers[signum] = previous
                    signal.signal(signum, terminate)
            entered = True
            self.write(ALTERNATE_SCREEN_ENTER)
            yield
        finally:
            try:
                if entered:
                    self.write(ALTERNATE_SCREEN_EXIT)
            finally:
                for signum, previous in previous_handlers.items():
                    signal.signal(signum, previous)

    def display(self, content: str, prompt: str) -> None:
        self.validate_screen(content, prompt)
        self.write(f"{CLEAR_SCREEN}{content.rstrip()}\n\n{prompt}")

    @contextmanager
    def immediate_input(self) -> Iterator[None]:
        original = termios.tcgetattr(self.input_fd)
        try:
            tty.setcbreak(self.input_fd, termios.TCSANOW)
            yield
        finally:
            termios.tcsetattr(self.input_fd, termios.TCSANOW, original)

    def read_sequence(self) -> bytes:
        first = os.read(self.input_fd, 1)
        if first != ESCAPE:
            return first

        sequence = bytearray(first)
        deadline = time.monotonic() + ESCAPE_SEQUENCE_TIMEOUT_SECONDS
        while len(sequence) < 3:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([self.input_fd], [], [], remaining)
            if not ready:
                break
            following = os.read(self.input_fd, 1)
            if not following:
                break
            sequence.extend(following)
        return bytes(sequence)

    def read_action(self) -> Action:
        while True:
            try:
                with self.immediate_input():
                    sequence = self.read_sequence()
            except KeyboardInterrupt:
                return Action.QUIT
            if not sequence:
                return Action.QUIT
            action = action_for(sequence)
            if action is not None:
                self.write(ERASE_PROMPT)
                return action
            self.write("\a")
