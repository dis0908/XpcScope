# XpcScope

Yet another xpc sniffer

![Screenshot](assets/screenshot.png)

## Setup

```shell
git clone --recurse-submodules https://github.com/ChiChou/XpcScope.git
```

### Build Frida Agent Script

This step requires node.js to be installed.

```shell
cd agent
npm install
npm run build
```

However, we provide a pre-built `agent/_agent.js` for your convenience, please check out the attachment in the
[releases page](https://github.com/ChiChou/XpcScope/releases).

### Install the Python package to a virtual environment

```shell
python3 -m venv .venv               # initialize virtual environment
source .venv/bin/activate           # active venv shell
pip install -e .                    # install all dependencies
```

## Run

XpcScope uses the same command-line flags as Frida for device and process selection.

### Attach by process name

```shell
xpcscope Finder | wireshark -k -i -
```

### Attach by PID

```shell
xpcscope -p 1234 | wireshark -k -i -
```

### Spawn a process and attach

```shell
xpcscope -f /usr/bin/sample_app | wireshark -k -i -
```

### Attach on a USB device (e.g. iOS)

```shell
xpcscope -U SpringBoard | wireshark -k -i -
```

### Attach on a remote device

```shell
xpcscope -H 192.168.1.100 Safari | wireshark -k -i -
```

### Device and target options

| Flag | Long | Description |
| ---- | -------------- | ---------------------------------------- |
| `-U` | `--usb` | Connect to USB device |
| `-R` | `--remote` | Connect to remote frida-server |
| `-D` | `--device ID` | Connect to device with the given ID |
| `-H` | `--host HOST` | Connect to remote frida-server on HOST |
| `-n` | `--attach-name NAME` | Attach to process by name |
| `-p` | `--attach-pid PID` | Attach to process by PID |
| `-f` | `--spawn PROGRAM` | Spawn a process and attach |
| `-s` | `--script MODULE` | Legacy: load a Python module with an `attach()` function |

The process name can also be passed as a positional argument (equivalent to `-n`).

### Using with uv

If you have [uv](https://docs.astral.sh/uv/):

```shell
uv run xpcscope Finder | wireshark -k -i -
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
