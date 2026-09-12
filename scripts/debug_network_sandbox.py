"""Locate native runtime crashes using only a synthetic sandbox fixture.

Run with a Cargo --message-format=json artifact stream. LLDB reports bounded
function names, never frame variables, registers, or process memory.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def diagnose(debugger):
    import lldb

    debugger.SetAsync(False)
    target = debugger.CreateTarget(os.environ["FACTORSEAL_DEBUG_TEST_EXECUTABLE"])
    if not target.IsValid():
        raise RuntimeError("cannot create sandbox probe target")
    with tempfile.TemporaryDirectory(prefix="factorseal-debug-") as directory:
        root = Path(directory).resolve()
        (root / "spool").mkdir()
        process = target.LaunchSimple(
            ["--exact", "isolation::sandbox::tests::sandbox_probe", "--nocapture"],
            [
                "FACTORSEAL_SANDBOX_TEST=runtime",
                f"FACTORSEAL_SANDBOX_FIXTURE={root}",
                f"FACTORSEAL_SANDBOX_PARENT={os.getpid()}",
                "RUST_TEST_THREADS=1",
            ],
            str(root),
        )
        if not process.IsValid():
            raise RuntimeError("cannot launch sandbox probe under LLDB")
        try:
            print(f"Sandbox probe process state: {process.GetState()}")
            if process.GetState() == lldb.eStateExited:
                print(f"Sandbox probe exit status: {process.GetExitStatus()}")
            for index in range(min(process.GetNumThreads(), 16)):
                thread = process.GetThreadAtIndex(index)
                print(f"Thread {index}, stop reason {thread.GetStopReason()}")
                for frame_index in range(min(thread.GetNumFrames(), 24)):
                    frame = thread.GetFrameAtIndex(frame_index)
                    print(f"  {frame_index}: {frame.GetFunctionName() or '<unknown>'}")
        finally:
            if process.GetState() != lldb.eStateExited:
                process.Kill()


def main():
    candidates = []
    with open(sys.argv[1], encoding="utf-8") as artifacts:
        for line in artifacts:
            artifact = json.loads(line)
            if (
                artifact.get("reason") == "compiler-artifact"
                and artifact.get("target", {}).get("name") == "factorseal"
                and "lib" in artifact.get("target", {}).get("kind", [])
                and artifact.get("profile", {}).get("test")
                and artifact.get("executable")
            ):
                candidates.append(artifact["executable"])
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one Factorseal library test executable")
    environment = dict(os.environ, FACTORSEAL_DEBUG_TEST_EXECUTABLE=candidates[0])
    subprocess.run(
        [
            "xcrun", "lldb", "--batch",
            "-o", f'command script import "{Path(__file__).resolve()}"',
            "-o", "script debug_network_sandbox.diagnose(lldb.debugger)",
        ],
        env=environment,
        check=True,
        timeout=180,
    )


if __name__ == "__main__":
    main()
