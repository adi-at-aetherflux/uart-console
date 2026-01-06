#!/usr/bin/env python3

import argparse
import glob
import re
import sys
import threading
import time
from datetime import datetime
from queue import Queue, Empty

import serial
from pyftdi.ftdi import Ftdi
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import Input, RichLog, Static


def list_devices():
    """List all connected FTDI devices and system serial ports."""
    print("Scanning for FTDI devices (via libusb)...")
    try:
        devices = Ftdi.list_devices()
        if devices:
            print(f"\nFound {len(devices)} FTDI device(s):\n")
            for i, (dev, interface_count) in enumerate(devices):
                vid = dev.vid
                pid = dev.pid
                serial_num = dev.sn or "N/A"
                description = dev.description or "N/A"
                print(f"  [{i}] VID:PID = {vid:04x}:{pid:04x}")
                print(f"      Serial: {serial_num}")
                print(f"      Description: {description}")
                print(f"      Interfaces: {interface_count}")
                if serial_num and serial_num != "N/A":
                    print(f"      URL: ftdi://ftdi:{pid:04x}:{serial_num}/1")
                else:
                    print(f"      URL: ftdi://ftdi:{pid:04x}/1")
                print()
        else:
            print("  No FTDI devices found via libusb.")
    except Exception as e:
        print(f"  Error scanning FTDI devices: {e}")

    print("\nSystem serial ports:")
    ports = sorted(glob.glob("/dev/cu.usb*") + glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))
    if ports:
        for port in ports:
            print(f"  {port}")
    else:
        print("  No USB serial ports found.")

    print("\nNote: On macOS, use system serial ports (/dev/cu.*) as the kernel")
    print("      driver claims FTDI devices. Use ftdi:// URLs only if you've")
    print("      unloaded the Apple FTDI driver.")


def parse_message(msg: str) -> bytes:
    """Parse a message string to bytes, supporting various formats."""
    msg = msg.strip()

    if msg.startswith("0x") or re.match(r'^[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2})*$', msg):
        hex_str = msg.replace("0x", "").replace(",", " ")
        try:
            return bytes.fromhex(hex_str.replace(" ", ""))
        except ValueError:
            pass

    try:
        return msg.encode('utf-8').decode('unicode_escape').encode('latin-1')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return msg.encode('utf-8')


def open_port(device: str, baudrate: int):
    """Open a serial port."""
    if device.startswith("ftdi://"):
        from pyftdi.serialext import serial_for_url
        return serial_for_url(device, baudrate=baudrate, timeout=0.05)
    else:
        return serial.Serial(device, baudrate=baudrate, timeout=0.05)


class UARTMonitorApp(App):
    """UART Monitor TUI Application."""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 1 4;
        grid-rows: 1 1fr 3 1;
    }

    #status-bar {
        height: 1;
        background: $surface;
        padding: 0 1;
    }

    #log-container {
        height: 100%;
        border: solid $primary;
    }

    #message-log {
        height: 100%;
        scrollbar-gutter: stable;
    }

    #input-container {
        height: 3;
        padding: 0 1;
    }

    #message-input {
        width: 100%;
    }

    #help-bar {
        height: 1;
        background: $surface;
        padding: 0 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+l", "clear_log", "Clear"),
        Binding("ctrl+x", "toggle_hex", "Hex"),
        Binding("ctrl+p", "stop_periodic", "Stop Periodic"),
        Binding("escape", "focus_input", "Focus Input"),
    ]

    def __init__(self, device: str, baudrate: int, hex_mode: bool = False,
                 timestamp: bool = True, line_ending: str = "crlf"):
        super().__init__()
        self.device = device
        self.baudrate = baudrate
        self.hex_mode = hex_mode
        self.show_timestamp = timestamp
        self.line_ending = line_ending
        self.port = None
        self.running = False
        self.tx_count = 0
        self.rx_count = 0
        self.endings = {"none": b"", "cr": b"\r", "lf": b"\n", "crlf": b"\r\n"}

        # Message queue for thread-safe communication
        self.rx_queue: Queue = Queue()

        # Reader thread
        self.reader_thread = None

        # Periodic sending - list of active periodic senders
        # Each entry: {"id": int, "thread": Thread, "stop": Event, "msg": str, "period_ms": float}
        self.periodic_senders = []

        # RX buffer for line assembly
        self.rx_buffer = b""
        self.last_rx_time = 0.0

    def compose(self) -> ComposeResult:
        yield Static(id="status-bar")
        yield Container(
            RichLog(id="message-log", highlight=True, markup=True, wrap=True),
            id="log-container"
        )
        yield Container(
            Input(placeholder="Type message and press Enter (or :help for commands)", id="message-input"),
            id="input-container"
        )
        yield Static(
            "[dim]Ctrl+C[/] Quit  [dim]Ctrl+L[/] Clear  [dim]Ctrl+X[/] Hex  "
            "[dim]Ctrl+P[/] Stop Periodic  [dim]:help[/] Commands",
            id="help-bar"
        )

    def on_mount(self) -> None:
        self.status_bar = self.query_one("#status-bar", Static)
        self.message_log = self.query_one("#message-log", RichLog)
        self.message_input = self.query_one("#message-input", Input)

        self.status_bar.update(f"[yellow]Connecting to {self.device}...[/]")
        self.connect_device()

        # Poll for received data every 50ms
        self.set_interval(0.05, self.poll_rx_queue)

    def connect_device(self) -> None:
        try:
            self.port = open_port(self.device, self.baudrate)
            self.running = True
            self.update_status()
            self.log_info(f"Connected to {self.device} at {self.baudrate} baud")
            self.start_reader_thread()
            self.message_input.focus()
        except Exception as e:
            self.status_bar.update(f"[red]● Connection failed: {e}[/]")
            self.log_error(f"Failed to connect: {e}")

    def start_reader_thread(self) -> None:
        """Start background thread to read serial data."""
        def reader():
            while self.running and self.port:
                try:
                    data = self.port.read(256)
                    if data:
                        self.rx_queue.put(("rx", data))
                except Exception as e:
                    if self.running:
                        self.rx_queue.put(("error", str(e)))
                    break

        self.reader_thread = threading.Thread(target=reader, daemon=True)
        self.reader_thread.start()

    def poll_rx_queue(self) -> None:
        """Poll the RX queue and display received data."""
        messages_processed = 0
        current_time = time.time()

        # Process all pending messages
        while messages_processed < 100:  # Limit to prevent UI freeze
            try:
                msg_type, data = self.rx_queue.get_nowait()
                messages_processed += 1

                if msg_type == "rx":
                    self.rx_count += len(data)
                    self.last_rx_time = current_time

                    if self.hex_mode:
                        self.log_rx(data)
                    else:
                        self.rx_buffer += data
                        # Process complete lines
                        while b"\n" in self.rx_buffer:
                            line, self.rx_buffer = self.rx_buffer.split(b"\n", 1)
                            self.log_rx(line)

                elif msg_type == "error":
                    self.log_error(data)

                elif msg_type == "tx":
                    self.log_tx(data)

            except Empty:
                break

        # Flush RX buffer if no new data for 100ms
        if self.rx_buffer and (current_time - self.last_rx_time) > 0.1:
            self.log_rx(self.rx_buffer)
            self.rx_buffer = b""

        # Update status if we processed any messages
        if messages_processed > 0:
            self.update_status()

    def update_status(self) -> None:
        periodic_status = ""
        if self.periodic_senders:
            periodic_parts = [f"[{s['id']}]:{s['period_ms']}ms" for s in self.periodic_senders]
            periodic_status = f" | [yellow]Periodic: {', '.join(periodic_parts)}[/]"

        self.status_bar.update(
            f"[green]●[/] {self.device} @ {self.baudrate} | "
            f"TX: {self.tx_count} | RX: {self.rx_count} | "
            f"Hex: {'on' if self.hex_mode else 'off'}{periodic_status}"
        )

    def format_timestamp(self) -> str:
        if self.show_timestamp:
            return datetime.now().strftime("%H:%M:%S.%f")[:-3]
        return ""

    def log_tx(self, data: bytes) -> None:
        ts = self.format_timestamp()
        if self.hex_mode:
            content = " ".join(f"{b:02x}" for b in data)
        else:
            content = data.decode("utf-8", errors="replace").rstrip("\r\n")

        if ts:
            self.message_log.write(f"[dim]{ts}[/] [green]TX →[/] {content}")
        else:
            self.message_log.write(f"[green]TX →[/] {content}")

    def log_rx(self, data: bytes) -> None:
        ts = self.format_timestamp()
        if self.hex_mode:
            content = " ".join(f"{b:02x}" for b in data)
        else:
            content = data.decode("utf-8", errors="replace").rstrip("\r\n")

        if ts:
            self.message_log.write(f"[dim]{ts}[/] [cyan]RX ←[/] {content}")
        else:
            self.message_log.write(f"[cyan]RX ←[/] {content}")

    def log_info(self, message: str) -> None:
        ts = self.format_timestamp()
        if ts:
            self.message_log.write(f"[dim]{ts}[/] [dim]{message}[/]")
        else:
            self.message_log.write(f"[dim]{message}[/]")

    def log_error(self, message: str) -> None:
        ts = self.format_timestamp()
        if ts:
            self.message_log.write(f"[dim]{ts}[/] [red]ERROR: {message}[/]")
        else:
            self.message_log.write(f"[red]ERROR: {message}[/]")

    def send_data(self, data: bytes) -> None:
        """Send data to the device."""
        if self.port:
            try:
                line_end = self.endings.get(self.line_ending, b"\r\n")
                full_data = data + line_end
                self.port.write(full_data)
                self.port.flush()
                self.tx_count += len(full_data)
                self.log_tx(data)
                self.update_status()
            except Exception as e:
                self.log_error(f"Send failed: {e}")

    def start_periodic(self, message: str, period_ms: float) -> None:
        """Start a new periodic message sender."""
        # Find the lowest available ID (reuse IDs from stopped senders)
        used_ids = {s["id"] for s in self.periodic_senders}
        sender_id = 1
        while sender_id in used_ids:
            sender_id += 1

        data = parse_message(message)
        line_end = self.endings.get(self.line_ending, b"\r\n")
        full_data = data + line_end
        period_sec = period_ms / 1000.0

        stop_event = threading.Event()

        sender_info = {
            "id": sender_id,
            "thread": None,
            "stop": stop_event,
            "msg": message,
            "period_ms": period_ms
        }

        def sender():
            while not stop_event.is_set() and self.running:
                if self.port:
                    try:
                        self.port.write(full_data)
                        self.port.flush()
                        self.tx_count += len(full_data)
                        self.rx_queue.put(("tx", data))
                    except Exception as e:
                        self.rx_queue.put(("error", f"Periodic [{sender_id}] failed: {e}"))
                        break
                stop_event.wait(period_sec)

        thread = threading.Thread(target=sender, daemon=True)
        sender_info["thread"] = thread
        self.periodic_senders.append(sender_info)
        thread.start()

        self.log_info(f"Periodic [{sender_id}] started: '{message}' every {period_ms}ms")
        self.update_status()

    def stop_periodic_send(self, sender_id: int = None) -> None:
        """Stop periodic message sending.

        Args:
            sender_id: If provided, stop only that sender. If None, stop all.
        """
        if sender_id is not None:
            # Stop specific sender
            sender = next((s for s in self.periodic_senders if s["id"] == sender_id), None)
            if sender:
                sender["stop"].set()
                sender["thread"].join(timeout=1)
                self.periodic_senders.remove(sender)
                self.log_info(f"Periodic [{sender_id}] stopped")
            else:
                self.log_error(f"No periodic sender with ID {sender_id}")
        else:
            # Stop all senders
            if not self.periodic_senders:
                self.log_info("No periodic senders active")
                return
            for sender in self.periodic_senders:
                sender["stop"].set()
                sender["thread"].join(timeout=1)
            count = len(self.periodic_senders)
            self.periodic_senders.clear()
            self.log_info(f"Stopped all {count} periodic sender(s)")

        self.update_status()

    def show_help(self) -> None:
        """Display help message."""
        help_lines = [
            "",
            "[bold]Commands:[/]",
            "  :send <msg>              Send message once",
            "  :send :<period> <msg>    Send periodically (e.g. :send :500 hello)",
            "  :stop                    Stop all periodic senders",
            "  :stop <id>               Stop specific sender (e.g. :stop 1)",
            "  :hex on|off              Toggle hex display",
            "  :end none|cr|lf|crlf     Set line ending",
            "  :clear                   Clear log",
            "  :help                    Show this help",
            "  :quit                    Exit",
            "",
            "[bold]Message formats:[/]",
            "  hello                    Plain text",
            "  hello\\\\r\\\\n               Escape sequences",
            "  0x48 0x65 0x6c           Hex (0x prefix)",
            "  48 65 6c 6c 6f           Hex (space-separated)",
            "",
            "Just type text and press Enter to send.",
            "",
        ]
        for line in help_lines:
            self.message_log.write(line)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission."""
        text = event.value.strip()
        if not text:
            return

        self.message_input.value = ""

        if text.startswith(":"):
            self.handle_command(text[1:])
        else:
            data = parse_message(text)
            self.send_data(data)

    def handle_command(self, cmd_line: str) -> None:
        """Handle a command."""
        parts = cmd_line.split(maxsplit=2)
        cmd = parts[0].lower() if parts else ""

        if cmd in ("quit", "q"):
            self.action_quit()
        elif cmd == "help":
            self.show_help()
        elif cmd == "clear":
            self.message_log.clear()
        elif cmd == "stop":
            if len(parts) > 1:
                try:
                    sender_id = int(parts[1])
                    self.stop_periodic_send(sender_id)
                except ValueError:
                    self.log_error("Usage: :stop or :stop <id>")
            else:
                self.stop_periodic_send()
        elif cmd == "hex":
            if len(parts) > 1:
                self.hex_mode = parts[1].lower() in ("on", "true", "1")
            else:
                self.hex_mode = not self.hex_mode
            self.log_info(f"Hex mode: {'on' if self.hex_mode else 'off'}")
            self.update_status()
        elif cmd == "end":
            if len(parts) > 1 and parts[1].lower() in self.endings:
                self.line_ending = parts[1].lower()
                self.log_info(f"Line ending: {self.line_ending}")
            else:
                self.log_error("Usage: :end none|cr|lf|crlf")
        elif cmd == "send":
            if len(parts) < 2:
                self.log_error("Usage: :send <message> or :send :<period_ms> <message>")
            elif parts[1].startswith(":"):
                # Periodic send format: :send :<period> <message>
                try:
                    period_ms = float(parts[1][1:])  # Remove the leading ':'
                    if len(parts) < 3:
                        self.log_error("Usage: :send :<period_ms> <message>")
                    else:
                        message = parts[2]
                        self.start_periodic(message, period_ms)
                except ValueError:
                    self.log_error("Invalid period. Usage: :send :<period_ms> <message>")
            else:
                # One-shot send: :send <message>
                # Rejoin all parts after 'send' as the message
                message = cmd_line[len("send"):].strip()
                data = parse_message(message)
                self.send_data(data)
        else:
            self.log_error(f"Unknown command: {cmd}. Type :help for commands.")

    def action_quit(self) -> None:
        self.running = False
        self.stop_periodic_send()
        if self.port:
            self.port.close()
        self.exit()

    def action_clear_log(self) -> None:
        self.message_log.clear()

    def action_toggle_hex(self) -> None:
        self.hex_mode = not self.hex_mode
        self.log_info(f"Hex mode: {'on' if self.hex_mode else 'off'}")
        self.update_status()

    def action_stop_periodic(self) -> None:
        self.stop_periodic_send()

    def action_focus_input(self) -> None:
        self.message_input.focus()


def main():
    parser = argparse.ArgumentParser(
        description="UART Monitor TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                              # List available devices
  %(prog)s /dev/cu.usbserial-AB9EUUYE          # Open TUI monitor
  %(prog)s /dev/cu.usbserial-AB9EUUYE --hex    # Start in hex mode
  %(prog)s /dev/cu.usbserial-AB9EUUYE -b 9600  # Custom baud rate
        """
    )

    parser.add_argument("device", nargs="?", default=None,
                        help="Serial port (/dev/cu.xxx) or FTDI URL (ftdi://...)")
    parser.add_argument("-b", "--baudrate", type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List available devices")
    parser.add_argument("--hex", action="store_true",
                        help="Start in hex display mode")
    parser.add_argument("-t", "--timestamp", action="store_true", default=True,
                        help="Show timestamps (default: on)")
    parser.add_argument("--no-timestamp", action="store_false", dest="timestamp",
                        help="Hide timestamps")
    parser.add_argument("-e", "--line-ending", choices=["none", "cr", "lf", "crlf"],
                        default="crlf", help="Line ending for sent messages (default: crlf)")

    args = parser.parse_args()

    if args.list:
        list_devices()
        return

    if not args.device:
        parser.print_help()
        print("\nError: Device required (or use --list to find devices)")
        sys.exit(1)

    app = UARTMonitorApp(
        device=args.device,
        baudrate=args.baudrate,
        hex_mode=args.hex,
        timestamp=args.timestamp,
        line_ending=args.line_ending
    )
    app.run()


if __name__ == "__main__":
    main()
