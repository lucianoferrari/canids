# canids — CAN Bus Intrusion Detection (proof of concept)

A small, readable intrusion-detection script for automotive CAN bus traffic, written to teach detection concepts in the [LufSec Car Hacking course](https://lufsec.com). It watches a CAN interface via `candump` and flags **brute-force / fuzzing behaviour** — an attacker walking a CAN ID's payload through sequential values to discover which one unlocks a door, moves a gauge, or triggers an ECU function.

It is deliberately simple: one file, no dependencies beyond `can-utils`, and logic you can read in five minutes and extend in an afternoon.

```
     _            __ _____
    | |          / _/ ____|
    | |    _   _| || (___   ___  ___
    | |   | | | |  _\___ \ / _ \/ __|
    | |___| |_| | | ____) |  __/ (__
    |______\__,_|_||_____/ \___|\___|

LufSec CAN Bus IDS
Monitoring CAN traffic on vcan0 for brute-force attempts.
Brute-force detected on CAN ID: 19B, Data: 00000F000000
Brute-force detected on CAN ID: 19B, Data: 000010000000
Brute-force detected on CAN ID: 19B, Data: 000011000000
```

## Why this matters

CAN has no authentication, no encryption, and no sender address. Any node on the bus can transmit any arbitration ID with any payload, and the receiving ECU will act on it. Once an attacker has a foothold (infotainment, telematics, the OBD-II port), the quickest way to find a useful message is to pick an ID and iterate the payload until something happens. That pattern — the same ID, payload incrementing by one, frame after frame — almost never occurs in legitimate traffic, which makes it a high-signal, low-noise thing to detect.

## How it works

1. Spawns `candump <interface>` and reads frames line by line.
2. Parses each line into `(can_id, data)` with a regex (`vcan0  19B   [8]  00 00 0F 00 00 00 00 00`).
3. Keeps the last payload seen for every CAN ID.
4. If the new payload equals the previous payload **+ 1** (interpreted as a hex integer), it raises a brute-force alert for that ID.
5. Maintains a per-ID frame counter (`can_id_seen_count`) as a hook for frequency-based detections.

CAN ID `0x244` is skipped by default because in the [ICSim](https://github.com/zombieCraig/ICSim) simulator it carries a legitimately incrementing counter (speedometer) that would otherwise trip the detector — a built-in lesson about baselining before alerting.

## Quick start (ICSim lab)

```bash
# 1. Dependencies (Debian/Ubuntu/Kali)
sudo apt install can-utils
# plus ICSim: https://github.com/zombieCraig/ICSim

# 2. Virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 3. Start the simulator and controller in two terminals
./icsim vcan0
./controls vcan0

# 4. Run the IDS in a third terminal
python3 canids.py vcan0

# 5. In a fourth terminal, simulate a brute-force attack and watch the alerts
for i in $(seq 0 255); do cansend vcan0 19B#$(printf '%012X' $i); sleep 0.05; done
```

Works the same against a physical bus (`can0` via a USB-CAN adapter) — the script doesn't care whether the interface is virtual or real.

## What it does *not* do (yet)

This is a teaching PoC, not a production IDS. Natural extensions, roughly in the order I'd build them:

- **Baseline learning** — record normal traffic for N seconds, then alert on CAN IDs never seen during baseline
- **Frequency / cadence detection** — most CAN messages are periodic; alert when an ID's inter-arrival time deviates from its learned cadence (replay and injection attacks disturb timing even when payloads look valid)
- **Payload range checks** — per-signal plausibility (a speed value that jumps 0→200 km/h in one frame)
- **Correlated alerting** — require two weak signals (cadence + payload) before alerting, to cut false positives on a moving vehicle
- **DBC-aware decoding** — map IDs/signals to names for readable alerts
- **Structured output** — JSON lines for shipping to a SIEM

Pull requests implementing any of these are welcome.

## Files

| File | Purpose |
|---|---|
| `canids.py` | The IDS (Python 3, stdlib only; requires `candump` from can-utils on PATH) |

## Related

- [What Building a CAN Bus IDS Taught Me About Detection Engineering](https://github.com/lucianoferrari/security-writing/blob/main/essays/what-a-can-bus-ids-taught-me-about-detection.md) — the lessons behind this project
- [LufSec Car Hacking course](https://lufsec.com) — where this is used as a lab
- [ICSim](https://github.com/zombieCraig/ICSim) — the instrument-cluster simulator used for the lab

## License

MIT © Luciano Ferrari
