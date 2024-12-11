import subprocess
import re
import sys

def print_banner():
    """
    Prints the banner for the program.
    """
    banner = """
     _            __ _____           
    | |          / _/ ____|          
    | |    _   _| || (___   ___  ___ 
    | |   | | | |  _\___ \ / _ \/ __|
    | |___| |_| | | ____) |  __/ (__ 
    |______\__,_|_||_____/ \___|\___|
                                      
    """
    print(banner)
    print("LufSec CAN Bus IDS")
    print("Developed by Luciano Ferrari\n")

# Check if the user has provided an interface argument
if len(sys.argv) != 2:
    print("Usage: python3 can_ids.py <interface>")
    sys.exit(1)

INTERFACE = sys.argv[1]

# This dictionary will hold the last data value seen for each CAN ID
last_data_values = {}
# This dictionary will track how many times each CAN ID has been seen
can_id_seen_count = {}

def parse_candump_line(line):
    """
    Parse a line from candump output and return the CAN ID and data.
    Example line: "vcan0 188   [1]  BA"
    """
    match = re.search(r"(\w+)\s+(\w+)\s+\[\d+\]\s+([\w\s]+)", line)
    if match:
        interface, can_id, data = match.groups()
        data = data.replace(" ", "")  # Remove spaces from data
        return can_id, data
    return None, None

def is_incremental(old_data, new_data):
    """
    Checks if the new_data is an incremental step from old_data.
    Assumes data is represented in hexadecimal.
    """
    try:
        old_val = int(old_data, 16)
        new_val = int(new_data, 16)
        return (new_val - old_val) == 1
    except ValueError:
        # In case the data cannot be converted to integer
        return False

def monitor_can(interface):
    """
    Monitor CAN interface for packets using candump, detecting brute-force attempts.
    """
    with subprocess.Popen(["candump", interface], stdout=subprocess.PIPE, text=True) as proc:
        print(f"Monitoring CAN traffic on {interface} for brute-force attempts.")
        try:
            for line in proc.stdout:
                can_id, data = parse_candump_line(line.strip())
                if can_id and data:
                    # Skip detection for specific CAN ID 244
                    if can_id == "244":
                        continue

                    # Initialize the CAN ID counter if not already present
                    if can_id not in can_id_seen_count:
                        can_id_seen_count[can_id] = 0

                    # Increment the seen count for the CAN ID
                    can_id_seen_count[can_id] += 1

                    # Only check for brute-forcing
                    if can_id in last_data_values:
                        if is_incremental(last_data_values[can_id], data):
                            print(f"Brute-force detected on CAN ID: {can_id}, Data: {data}")

                    # Update the last seen data for this CAN ID
                    last_data_values[can_id] = data
        except KeyboardInterrupt:
            print("\nStopped monitoring.")

if __name__ == "__main__":
    print_banner()
    monitor_can(INTERFACE)
