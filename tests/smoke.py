#!/usr/bin/env python3
"""Headless smoke test — attach to a process, collect XPC/NSXPC messages,
and print a summary. No Wireshark required.

Usage:
    uv run python tests/smoke.py -U -n SpringBoard        # USB + process name
    uv run python tests/smoke.py -n rapportd               # local + process name
    uv run python tests/smoke.py -U -p 1                   # USB + PID
    uv run python tests/smoke.py -U -n SpringBoard -t 10   # collect for 10s
"""

import argparse
import json
import signal
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import frida

AGENT_JS = Path(__file__).resolve().parent.parent / "xpcscope" / "agent" / "_agent.js"


def main():
    parser = argparse.ArgumentParser(description="Headless XpcScope smoke test")
    device_group = parser.add_mutually_exclusive_group()
    device_group.add_argument("-U", "--usb", action="store_true", help="USB device")
    device_group.add_argument("-R", "--remote", action="store_true", help="remote frida-server")
    device_group.add_argument("-D", "--device", metavar="ID", help="device ID")
    device_group.add_argument("-H", "--host", metavar="HOST", help="remote host")

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-p", "--attach-pid", metavar="PID", type=int, help="attach by PID")
    target_group.add_argument("-n", "--attach-name", metavar="NAME", help="attach by name")

    parser.add_argument("-t", "--timeout", type=float, default=5, help="seconds to collect (default: 5)")
    args = parser.parse_args()

    # connect
    if args.usb:
        device = frida.get_usb_device()
    elif args.remote:
        device = frida.get_remote_device()
    elif args.device:
        device = frida.get_device(args.device)
    elif args.host:
        device = frida.get_device_manager().add_remote_device(args.host)
    else:
        device = frida.get_local_device()

    target = args.attach_name or args.attach_pid
    print(f"[*] attaching to {target} on {device.name}...")
    session = device.attach(target)

    with AGENT_JS.open("r", encoding="utf8") as f:
        script = session.create_script(f.read())

    messages = []
    errors = []
    lock = threading.Lock()

    def on_message(message, data):
        with lock:
            if message["type"] == "send":
                messages.append(message["payload"])
            elif message["type"] == "error":
                errors.append(message.get("description", str(message)))

    def on_log(level, text):
        sys.stderr.write(f"[{level}] {text}\n")

    script.set_log_handler(on_log)
    script.on("message", on_message)

    print("[*] loading agent...")
    script.load()

    print("[*] calling start()...")
    script.exports_sync.start()
    print(f"[+] hooks installed, collecting for {args.timeout}s...")

    stop = threading.Event()

    def handler(sig, frame):
        stop.set()

    signal.signal(signal.SIGINT, handler)
    stop.wait(timeout=args.timeout)

    # tear down
    script.unload()
    session.detach()

    # report
    print()
    print("=" * 60)
    print("SMOKE TEST RESULTS")
    print("=" * 60)

    if errors:
        print(f"\n[!] ERRORS ({len(errors)}):")
        for e in errors[:10]:
            print(f"    {e[:200]}")
        if len(errors) > 10:
            print(f"    ... and {len(errors) - 10} more")

    xpc_msgs = [m for m in messages if m.get("message", {}).get("type") != "nsxpc"]
    nsxpc_msgs = [m for m in messages if m.get("message", {}).get("type") == "nsxpc"]
    other_msgs = [m for m in messages if "message" not in m and "event" not in m]

    print(f"\n    total messages: {len(messages)}")
    print(f"    XPC (low-level): {len(xpc_msgs)}")
    print(f"    NSXPC (high-level): {len(nsxpc_msgs)}")
    if other_msgs:
        print(f"    other: {len(other_msgs)}")

    if nsxpc_msgs:
        print(f"\n[+] NSXPC messages ({len(nsxpc_msgs)}):")
        dirs = Counter(m.get("dir", "?") for m in nsxpc_msgs)
        for d, c in dirs.most_common():
            label = "incoming" if d == "<" else "outgoing" if d == ">" else d
            print(f"    {label}: {c}")

        sels = Counter(m.get("message", {}).get("sel", "?") for m in nsxpc_msgs)
        print(f"\n    top selectors:")
        for sel, c in sels.most_common(10):
            print(f"      {c:4d}  {sel}")

        services = Counter(m.get("name", "") for m in nsxpc_msgs)
        if any(s for s in services):
            print(f"\n    services:")
            for svc, c in services.most_common(10):
                print(f"      {c:4d}  {svc or '(anonymous)'}")

        print(f"\n    sample messages:")
        for m in nsxpc_msgs[:5]:
            desc = m.get("message", {}).get("description", "")
            d = m.get("dir", "?")
            print(f"      {d} {desc[:120]}")

    if xpc_msgs:
        print(f"\n[+] XPC messages ({len(xpc_msgs)}):")
        events = Counter(m.get("event", "?") for m in xpc_msgs)
        for ev, c in events.most_common():
            print(f"    {ev}: {c}")

    # verdict
    print()
    ok = len(errors) == 0 and len(messages) > 0
    if ok:
        print("[PASS] agent loaded, hooks fired, messages captured")
    elif len(errors) == 0 and len(messages) == 0:
        print("[WARN] agent loaded with no errors but no messages captured")
        print("       (try increasing --timeout or picking a busier process)")
    else:
        print("[FAIL] errors detected")
    print()

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
