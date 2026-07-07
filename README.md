# XpcScope

Yet another xpc sniffer

![Screenshot](assets/screenshot.png)

## Setup

```shell
git clone --recurse-submodules https://github.com/ChiChou/XpcScope.git
cd XpcScope
```

### Install

With [uv](https://docs.astral.sh/uv/) (recommended):

```shell
uv run xpcscope -U SpringBoard
```

Dependencies are resolved automatically on first run.

The Frida agent (`_agent.js`) is built automatically during install. If Node.js
is available, it compiles from source; otherwise, a pre-built binary is
downloaded from the [matching GitHub release](https://github.com/ChiChou/XpcScope/releases).

<details>
<summary>With pip</summary>

```shell
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

</details>

## Usage

XpcScope uses the same command-line flags as Frida for device and process selection.
Wireshark is launched automatically.

```shell
xpcscope Finder                        # attach by name (local)
xpcscope -p 1234                       # attach by PID
xpcscope -f /usr/bin/sample_app        # spawn and attach
xpcscope -U SpringBoard                # USB device (iOS)
xpcscope -H 192.168.1.100 Safari       # remote frida-server
```

### Options

| Flag | Long | Description |
| ---- | -------------- | ---------------------------------------- |
| `-U` | `--usb` | Connect to USB device |
| `-R` | `--remote` | Connect to remote frida-server |
| `-D` | `--device ID` | Connect to device with the given ID |
| `-H` | `--host HOST` | Connect to remote frida-server on HOST |
| `-n` | `--attach-name NAME` | Attach to process by name |
| `-p` | `--attach-pid PID` | Attach to process by PID |
| `-f` | `--spawn PROGRAM` | Spawn a process and attach |
| `-s` | `--script MODULE` | Load a Python module with an `attach()` function |

The process name can also be passed as a positional argument (equivalent to `-n`).

### Headless smoke test

Run without Wireshark to verify hooks are working:

```shell
uv run python tests/smoke.py -U -n SpringBoard -t 10
```

## Wireshark Display Filters

The dissector registers the following fields for filtering:

| Field         | Type   | Description                  |
| ------------- | ------ | ---------------------------- |
| `xpc.name`    | string | XPC service name             |
| `xpc.dir`     | string | `>` (sent) or `<` (received) |
| `xpc.event`   | string | `sent` or `received`         |
| `xpc.peer`    | int    | Remote peer PID              |
| `xpc.msgtype` | string | `dictionary`, `nsxpc`, etc.  |
| `xpc.sel`     | string | NSXPC selector (NSXPC only)  |

Examples:

```
xpc.name == "com.apple.windowserver"
xpc.name contains "apple"
xpc.dir == ">"
xpc.peer == 372
xpc.msgtype == "nsxpc"
xpc.sel contains "fetch"
```
