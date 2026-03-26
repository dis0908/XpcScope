#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import BinaryIO, Callable

import frida

from xpcscope.pcap import Pcap

PROJECT_ROOT = Path(__file__).parent.parent


def deploy_plugin():
    # install dissector to Wireshark
    # if windows
    def location():
        if sys.platform == "win32":
            return Path(os.environ["APPDATA"]) / "Wireshark" / "plugins"
        return Path.home() / ".local" / "lib" / "wireshark" / "plugins"

    plugins = location()
    if not plugins.exists():
        plugins.mkdir(parents=True, exist_ok=True)

    shutil.copy(PROJECT_ROOT / "lua" / "xpc.lua", plugins / "xpc.lua")
    json_dir = plugins / "json"
    if not json_dir.exists():
        json_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(PROJECT_ROOT / "lua" / "json" / "json.lua", json_dir / "json.lua")


def tool(get_target: Callable[[], frida.core.Session], output: BinaryIO = sys.stdout.buffer):
    session = get_target()

    source = PROJECT_ROOT / "agent" / "_agent.js"
    try:
        with source.open("r", encoding="utf8") as f:
            script = session.create_script(f.read())
    except FileNotFoundError:
        sys.stderr.write(f"frida agent {source} not found\n")
        return

    pcap = Pcap(output)

    def on_message(message: dict, data: bytes):
        if message["type"] == "send":
            not_null_data = data if data is not None else b""
            metadata = json.dumps(message["payload"])
            joint = metadata.encode("utf8") + not_null_data
            ok = pcap.write(joint, len(not_null_data))
            if not ok:
                os.kill(os.getpid(), signal.SIGINT)
                return

        elif (
            message["type"] == "error"
            and "description" in message
            and "unable to find module 'libobjc.A.dylib'" in message["description"]
        ):
            sys.stderr.write(
                "Script successfully injected but the target does not have ObjC runtine.\n"
            )
            sys.stderr.write("You are likely injecting to a wrong platform binary.\n")
            os.kill(os.getpid(), signal.SIGINT)
            return
        else:
            sys.stderr.write(f"{message}\n")

    def logger(level, text):
        sys.stderr.write(f"[{level}] {text}\n")

    script.set_log_handler(logger)
    script.on("message", on_message)
    script.load()
    pcap.write_header()
    script.exports_sync.start()
    # name, pid = script.exports_sync.name_and_pid()
    # sys.stderr.write(f'attached to {name}({pid})\n')

    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        script.unload()
        session.detach()


def get_device(args) -> frida.core.Device:
    if args.usb:
        return frida.get_usb_device()
    elif args.remote:
        return frida.get_remote_device()
    elif args.device is not None:
        return frida.get_device(args.device)
    elif args.host is not None:
        mgr = frida.get_device_manager()
        return mgr.add_remote_device(args.host)
    else:
        return frida.get_local_device()


def cli():
    parser = argparse.ArgumentParser(
        description="XPC sniffer powered by Frida. Launches Wireshark automatically.",
        usage="xpcscope [options] target",
    )

    # Device selection (mutually exclusive)
    device_group = parser.add_mutually_exclusive_group()
    device_group.add_argument(
        "-U", "--usb", action="store_true", help="connect to USB device"
    )
    device_group.add_argument(
        "-R", "--remote", action="store_true", help="connect to remote frida-server"
    )
    device_group.add_argument(
        "-D", "--device", metavar="ID", help="connect to device with the given ID"
    )
    device_group.add_argument(
        "-H", "--host", metavar="HOST", help="connect to remote frida-server on HOST"
    )

    # Target selection
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-p", "--attach-pid", metavar="PID", type=int, help="attach to process by PID"
    )
    target_group.add_argument(
        "-n",
        "--attach-name",
        metavar="NAME",
        help="attach to process by name",
    )
    target_group.add_argument(
        "-f", "--spawn", metavar="PROGRAM", help="spawn a process and attach"
    )
    target_group.add_argument(
        "-s",
        "--script",
        metavar="MODULE",
        help="legacy mode: load a Python module with an attach() function",
    )

    # Positional: process name (alternative to -n)
    parser.add_argument(
        "target",
        nargs="?",
        help="process name to attach to (same as -n)",
    )

    args = parser.parse_args()

    deploy_plugin()

    # Launch Wireshark, feeding PCAP into its stdin
    wireshark = subprocess.Popen(
        ["wireshark", "-k", "-i", "-"],
        stdin=subprocess.PIPE,
    )

    def run_tool(get_target_fn):
        try:
            tool(get_target_fn, wireshark.stdin)
        finally:
            wireshark.stdin.close()
            wireshark.wait()

    # Legacy script mode
    if args.script is not None:
        name = args.script
        sys.path.append(os.path.dirname(os.path.abspath(name)))
        try:
            loader = __import__(os.path.basename(name))
        except ImportError:
            sys.stderr.write(f"Cannot import module '{name}'\n")
            sys.exit(1)
        try:
            run_tool(getattr(loader, "attach"))
        except AttributeError:
            sys.stderr.write(f"Module '{name}' does not have an 'attach' function\n")
            sys.exit(1)
        return

    # Determine target
    target_name = args.attach_name or args.target
    target_pid = args.attach_pid
    spawn_target = args.spawn

    if target_name is None and target_pid is None and spawn_target is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    def attach() -> frida.core.Session:
        device = get_device(args)
        if spawn_target is not None:
            pid = device.spawn([spawn_target])
            session = device.attach(pid)
            device.resume(pid)
            return session
        elif target_pid is not None:
            return device.attach(target_pid)
        else:
            return device.attach(target_name)

    run_tool(attach)


if __name__ == "__main__":
    cli()
