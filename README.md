# UART Monitor

A terminal-based UART monitor with a modern TUI interface for monitoring and interacting with serial devices.

### From source

```bash
git clone <repository-url>
cd uart_monitor_pkg
pip install -e . 
```

## Requirements

- Python 3.8+
- pyftdi
- pyserial
- textual

## Usage

### List available devices

```bash
uart-monitor --list
```

### Connect to a device

```bash
# Using system serial port (recommended on macOS)
uart-monitor /dev/cu.usbserial-XXXXX
```

### Options

```bash
uart-monitor <device> [options]

Options:
  -b, --baudrate RATE    Baud rate (default: 115200)
  --hex                  Start in hex display mode
  -t, --timestamp        Show timestamps (default: on)
  --no-timestamp         Hide timestamps
  -e, --line-ending      Line ending: none, cr, lf, crlf (default: crlf)
  -l, --list             List available devices
```

## TUI Commands

Once connected, use these commands in the input field:

| Command | Description |
|---------|-------------|
| `:send <msg>` | Send a message once |
| `:send :<period> <msg>` | Send periodically (e.g., `:send :500 hello`) |
| `:stop` | Stop all periodic senders |
| `:stop <id>` | Stop a specific periodic sender |
| `:hex on\|off` | Toggle hex display mode |
| `:end none\|cr\|lf\|crlf` | Set line ending |
| `:clear` | Clear the log |
| `:help` | Show help |
| `:quit` | Exit |

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Quit |
| `Ctrl+L` | Clear log |
| `Ctrl+X` | Toggle hex mode |
| `Ctrl+P` | Stop periodic sending |
| `Escape` | Focus input field |

## Message Formats

The monitor supports multiple input formats:

- **Plain text**: `hello world`
- **Escape sequences**: `hello\r\n`
- **Hex with prefix**: `0x48 0x65 0x6c 0x6c 0x6f`
- **Hex without prefix**: `48 65 6c 6c 6f`
