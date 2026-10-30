# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exec a reviewed command only after the parent releases its audit gate.

This file is launched by absolute path with ``python -I``. It deliberately has
no Barragan imports, network behavior, or shell interpretation.
"""

import os
import select
import sys


def main(argv: list[str]) -> int:
    # The normal protocol remains a 30-second gate. A reviewed incident may
    # allow longer read-only provider proofs before GO; no command executes on
    # expiry, EOF, or an invalid timeout.
    timeout = 30
    command_index = 3
    if len(argv) >= 5 and argv[2].startswith("--gate-timeout="):
        raw = argv[2].removeprefix("--gate-timeout=")
        if not raw.isdecimal() or not 1 <= int(raw) <= 1200 or argv[3] != "--":
            return 2
        timeout = int(raw)
        command_index = 4
    elif len(argv) < 4 or argv[2] != "--":
        return 2
    try:
        gate_fd = int(argv[1])
        ready, _, _ = select.select([gate_fd], [], [], timeout)
        if not ready or os.read(gate_fd, 1) != b"G":
            return 3
        # There must be exactly one GO byte, followed by EOF. Do not run if
        # the parent accidentally sent a broader/unreviewed instruction.
        if os.read(gate_fd, 1) != b"":
            return 3
    except (OSError, ValueError):
        return 3
    finally:
        try:
            os.close(gate_fd)
        except (OSError, ValueError, UnboundLocalError):
            pass
    command = argv[command_index:]
    if not command or not os.path.isabs(command[0]):
        return 2
    os.execv(command[0], command)
    return 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
