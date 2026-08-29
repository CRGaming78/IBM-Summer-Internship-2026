import serial
import json
import time
import threading
import queue
import datetime
import requests
from collections import defaultdict

C5_PORT = 'COM4'
C6_PORT = 'COM6'
BAUD_RATE = 115200
API_URL = "http://localhost:8000/api/ingest"
RESCAN_INTERVAL = 60  # seconds between environment rescans

# Thread-safe queue for incoming frames
frame_queue = queue.Queue()

# Events to control reader threads
c5_capture_active = threading.Event()  # gates frame queuing
c5_reader_paused = threading.Event()   # when CLEAR, C5 reader stops reading serial entirely
c5_reader_paused.set()                 # start unpaused

def read_serial_port(port_name, ser, capture_event, pause_event=None):
    """Continuously reads lines from a serial port.
    If pause_event is provided and cleared, the thread stops reading entirely."""
    print(f"[{port_name}] Started listening...")
    while True:
        try:
            # If pause_event exists and is cleared, sleep and skip reads
            if pause_event and not pause_event.is_set():
                time.sleep(0.05)
                continue

            if ser.in_waiting:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if not line:
                    continue
                if line.startswith('{') and line.endswith('}'):
                    try:
                        data = json.loads(line)
                        if "frame_type" in data and capture_event.is_set():
                            frame_queue.put(data)
                        elif "frame_type" not in data:
                            print(f"[{port_name}] STATUS: {line}")
                    except json.JSONDecodeError:
                        pass
            else:
                time.sleep(0.01)
        except Exception as e:
            print(f"[{port_name}] Error: {e}")
            time.sleep(1)

def send_command(ser, cmd):
    ser.write((cmd + "\n").encode('utf-8'))
    ser.flush()

def create_serial(port):
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = BAUD_RATE
    ser.timeout = 2
    ser.open()
    return ser


# ── Scan + Analyze + Assign ─────────────────────────────────────────────────

def do_scan_and_assign(ser_c5, ser_c6, scan_number):
    """Send CMD_SCAN to C5 (synchronously reads the result),
    analyze channels, lock C6, and start C5 hopping.
    Returns (best_24, channels_5g) or None on failure."""

    # Fully pause the C5 reader thread so it doesn't consume scan data
    c5_capture_active.clear()
    c5_reader_paused.clear()
    time.sleep(0.2)  # let the reader thread notice and stop
    ser_c5.reset_input_buffer()

    print(f"\n{'='*50}")
    print(f"[Scan #{scan_number}] Scanning environment...")
    send_command(ser_c5, "CMD_SCAN")

    scan_data = None
    start_time = time.time()
    json_str = ""
    in_json = False

    while time.time() - start_time < 15:
        if ser_c5.in_waiting:
            line = ser_c5.readline().decode('utf-8', errors='ignore').strip()
            if line.startswith('{"status":"scan_results"'):
                json_str += line
                in_json = True
            elif in_json:
                json_str += line
                if line.endswith(']}'):
                    try:
                        scan_data = json.loads(json_str)
                    except Exception as e:
                        print(f"  Failed to parse scan JSON: {e}")
                    break
        else:
            time.sleep(0.05)

    if not scan_data or "networks" not in scan_data:
        print("  Scan failed. Keeping previous channel assignment.")
        # Resume reader thread
        c5_reader_paused.set()
        c5_capture_active.set()
        return None

    networks = scan_data["networks"]
    print(f"  Found {len(networks)} networks.")

    # Analyze 2.4GHz: find most crowded channel
    chan_counts_24 = defaultdict(int)
    channels_5g_set = set()

    for net in networks:
        ch = net["channel"]
        if ch <= 14:
            chan_counts_24[ch] += 1
        else:
            channels_5g_set.add(ch)

    best_24 = max(chan_counts_24.items(), key=lambda x: x[1])[0] if chan_counts_24 else 6
    channels_5g = sorted(channels_5g_set) if channels_5g_set else [36, 44, 149]

    print(f"  Best 2.4GHz channel: {best_24} ({chan_counts_24.get(best_24, 0)} APs)")
    print(f"  Active 5GHz channels: {channels_5g}")

    # Re-lock C6
    send_command(ser_c6, f"CMD_LOCK:{best_24}")
    print(f"  C6 locked to ch {best_24}")

    # Re-start C5 hopping
    hop_str = ",".join(map(str, channels_5g))
    send_command(ser_c5, f"CMD_HOP:{hop_str}")
    print(f"  C5 hopping on: {hop_str}")
    print(f"  Next rescan in {RESCAN_INTERVAL}s")
    print(f"{'='*50}\n")

    # Resume reader thread
    c5_reader_paused.set()
    c5_capture_active.set()
    return (best_24, channels_5g)


# ── Main ─────────────────────────────────────────────────────────────────────

def run_orchestrator_sync():
    print("=== Wireless Security Monitor Orchestrator ===")
    try:
        ser_c5 = create_serial(C5_PORT)
        print(f"Opened C5 on {C5_PORT}")
    except Exception as e:
        print(f"Could not open {C5_PORT}: {e}")
        return

    try:
        ser_c6 = create_serial(C6_PORT)
        print(f"Opened C6 on {C6_PORT}")
    except Exception as e:
        print(f"Could not open {C6_PORT}: {e}")
        return

    # ── Ping handshake ───────────────────────────────────────────────────
    print("\nSending PING to both ESP32s and waiting for READY signal...")
    c5_ready = False
    c6_ready = False
    start_wait = time.time()
    last_ping_time = 0

    while time.time() - start_wait < 15:
        if time.time() - last_ping_time > 1.0:
            if not c5_ready:
                send_command(ser_c5, "CMD_PING")
            if not c6_ready:
                send_command(ser_c6, "CMD_PING")
            last_ping_time = time.time()

        if not c5_ready and ser_c5.in_waiting:
            line = ser_c5.readline().decode('utf-8', errors='ignore').strip()
            print(f"[C5 LOG]: {line}")
            if "c5_ready" in line:
                print("-> C5 is ready!")
                c5_ready = True

        if not c6_ready and ser_c6.in_waiting:
            line = ser_c6.readline().decode('utf-8', errors='ignore').strip()
            print(f"[C6 LOG]: {line}")
            if "c6_ready" in line:
                print("-> C6 is ready!")
                c6_ready = True

        if c5_ready and c6_ready:
            break
        time.sleep(0.05)

    if not c5_ready or not c6_ready:
        print("\nERROR: Did not receive ready signal from both boards!")
        return

    # ── Initial scan ─────────────────────────────────────────────────────
    ser_c5.reset_input_buffer()
    ser_c6.reset_input_buffer()
    c5_capture_active.set()

    result = do_scan_and_assign(ser_c5, ser_c6, scan_number=1)
    if result is None:
        print("Initial scan failed. Using defaults.")
        send_command(ser_c6, "CMD_LOCK:6")
        send_command(ser_c5, "CMD_HOP:36,44,149")
        c5_reader_paused.set()
        c5_capture_active.set()

    # ── Start reader threads ─────────────────────────────────────────────
    # C5 reader gets pause_event so scans can fully stop it
    t_c5 = threading.Thread(target=read_serial_port, args=("C5", ser_c5, c5_capture_active, c5_reader_paused), daemon=True)
    # C6 reader never needs pausing
    t_c6 = threading.Thread(target=read_serial_port, args=("C6", ser_c6, c5_capture_active), daemon=True)
    t_c5.start()
    t_c6.start()

    print("[5] Setup complete. Starting continuous packet capture...\n")

    # ── Main loop: POST frames + periodic rescan ─────────────────────────
    session = requests.Session()
    post_ok = 0
    post_fail = 0
    last_error_msg = ""
    last_scan_time = time.time()
    scan_count = 1

    while True:
        # Check if it's time for a rescan
        if time.time() - last_scan_time >= RESCAN_INTERVAL:
            scan_count += 1
            do_scan_and_assign(ser_c5, ser_c6, scan_number=scan_count)
            last_scan_time = time.time()

        try:
            frame = frame_queue.get(timeout=1.0)
            if "timestamp" not in frame:
                frame["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            try:
                r = session.post(API_URL, json=frame, timeout=2)
                if r.status_code == 200:
                    post_ok += 1
                else:
                    post_fail += 1
                    err = r.text[:120]
                    if err != last_error_msg:
                        print(f"[POST ERROR {r.status_code}]: {err}")
                        last_error_msg = err
            except requests.exceptions.ConnectionError:
                post_fail += 1
                if last_error_msg != "connection_refused":
                    print("[POST ERROR]: Backend not running? Start it with: python main.py")
                    last_error_msg = "connection_refused"
            except Exception as e:
                post_fail += 1
                if str(e) != last_error_msg:
                    print(f"[POST ERROR]: {e}")
                    last_error_msg = str(e)
        except queue.Empty:
            if post_ok > 0 or post_fail > 0:
                print(f"[Stats] Sent: {post_ok} ok, {post_fail} failed, queue: {frame_queue.qsize()}")
                post_ok = 0
                post_fail = 0

if __name__ == "__main__":
    run_orchestrator_sync()
