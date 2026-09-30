"""
Windows Event Log CSV Parser
-----------------------------
Loads a CSV export of Windows Event Log entries and lets you count,
filter, and flag security-relevant activity.

CONFIGURE THESE to match your CSV's actual column headers.
Run the script once and read the printed column list, then adjust below.
"""

import csv
import os
import statistics
from collections import Counter


def get_desktop_path(filename):
    """Build a full path to a file on the current user's Desktop.

    Handles the common Windows case where OneDrive redirects the Desktop
    folder to something like 'OneDrive - Company Name\\Desktop' instead
    of the plain '~\\Desktop'.
    """
    home = os.path.expanduser("~")

    candidates = [os.path.join(home, "Desktop")]

    # OneDrive can redirect Desktop into a folder like
    # "OneDrive - Organization Name". Check for any
    # sibling folder starting with "OneDrive" that contains a Desktop dir.
    try:
        for entry in os.listdir(home):
            if entry.lower().startswith("onedrive"):
                candidates.append(os.path.join(home, entry, "Desktop"))
    except OSError:
        pass

    for path in candidates:
        if os.path.isdir(path):
            return os.path.join(path, filename)

    # Nothing found - fall back to the plain path and create it.
    fallback = candidates[0]
    os.makedirs(fallback, exist_ok=True)
    return os.path.join(fallback, filename)


# ---- Column name configuration (matches simulated_windows_events.csv) ----
EVENTID_FIELD = "EventID"
SOURCE_IP_FIELD = "SourceIP"
PROCESS_NAME_FIELD = "Process"      # holds the executable name, e.g. powershell.exe

# Event IDs commonly treated as security-relevant for SOC triage
CRITICAL_EVENT_IDS = {
    "4624",  # successful logon
    "4625",  # failed logon
    "4648",  # logon using explicit credentials
    "4688",  # process creation
    "4672",  # special privileges assigned to new logon
    "4697",  # service installed (Security log)
    "7045",  # service installed (System log)
    "4720",  # user account created
    "4728",  # member added to security-enabled global group
    "4732",  # member added to security-enabled local group
    "4740",  # user account locked out
    "4776",  # credential validation
    "1102",  # audit log cleared
}

SUSPICIOUS_TOOLS = ["powershell", "mimikatz", "psexec", "rundll32"]


def load_events(filepath):
    """Read the CSV file and return a list of events (each a dict)."""
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def filter_by_field(events, field, value):
    return [e for e in events if e.get(field, "").strip() == value]


def filter_contains(events, field, keyword):
    return [e for e in events if keyword.lower() in e.get(field, "").lower()]


def count_by_field(events, field):
    return Counter(e.get(field, "UNKNOWN") for e in events)


def print_events(events, limit=None):
    """Print a list of event dicts with a blank line between each one,
    so a wall of text doesn't run together on screen."""
    shown = events if limit is None else events[:limit]
    for e in shown:
        print(f"  {e}")
        print()
    if limit is not None and len(events) > limit:
        print(f"  ... and {len(events) - limit} more\n")


def write_report_csv(events, output_path):
    """Write a list of event dicts out to a CSV file."""
    if not events:
        print("Nothing to write - no matching events.")
        return
    fieldnames = list(events[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
    print(f"Wrote {len(events)} rows to {output_path}")


def generate_security_report(events, output_path=None):
    """Filter to security-relevant Event IDs and write an easy-to-view CSV report."""
    if output_path is None:
        output_path = get_desktop_path("security_report.csv")
    critical_events = [e for e in events if e.get(EVENTID_FIELD, "").strip() in CRITICAL_EVENT_IDS]
    print(f"\nFound {len(critical_events)} security-relevant events "
          f"(Event IDs: {sorted(CRITICAL_EVENT_IDS)})")
    write_report_csv(critical_events, output_path)
    return critical_events


def print_failed_logons(events):
    """Print every row where EventID is 4625 (failed logon)."""
    failed = filter_by_field(events, EVENTID_FIELD, "4625")
    print(f"\n{len(failed)} failed logon (4625) events:\n")
    print_events(failed)
    return failed


def filter_by_eventid(events, event_id):
    """Return every event matching a specific EventID (e.g. '4625')."""
    matches = filter_by_field(events, EVENTID_FIELD, event_id.strip())
    print(f"\n{len(matches)} events with EventID {event_id}:\n")
    print_events(matches)
    return matches


def find_anomalous_failed_logon_sources(events, min_count=5, stddev_multiplier=2):
    """Flag IP addresses AND usernames that appear an unusually high
    number of times in failed logon (4625) events.

    'Unusual' here means: at least `min_count` occurrences, AND more
    than `stddev_multiplier` standard deviations above the average
    count for that field - so the threshold adapts to your data
    instead of using one fixed number for every log file.
    """
    failed = filter_by_field(events, EVENTID_FIELD, "4625")

    for field_label, field in [("IP address", SOURCE_IP_FIELD), ("username", "User")]:
        counts = Counter(e.get(field, "UNKNOWN").strip() for e in failed)
        values = list(counts.values())

        print(f"\nAnomalous {field_label}(s) in failed logons:")

        # With very few distinct values, a single outlier skews the
        # average enough that stdev-based detection misses it - so
        # fall back to a plain "count >= min_count" rule instead.
        if len(values) < 4:
            flagged = {v: c for v, c in counts.items() if c >= min_count}
            if not flagged:
                print(f"  None found (too few distinct {field_label}s for statistics; "
                      f"no value reached the minimum of {min_count})")
            else:
                for value, count in sorted(flagged.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {value}: {count} failed logons")
            continue

        mean = statistics.mean(values)
        stdev = statistics.pstdev(values)
        threshold = mean + (stddev_multiplier * stdev)

        flagged = {
            value: count for value, count in counts.items()
            if count >= min_count and count > threshold
        }

        if not flagged:
            print(f"  None found (average count: {mean:.1f}, threshold: {threshold:.1f})")
        else:
            for value, count in sorted(flagged.items(), key=lambda x: x[1], reverse=True):
                print(f"  {value}: {count} failed logons (average: {mean:.1f})")

    return failed


def find_bruteforce_ips(events, threshold=5):
    """Flag any IP appearing in more than `threshold` failed logon (4625) events."""
    failed = filter_by_field(events, EVENTID_FIELD, "4625")
    ip_counts = Counter(e.get(SOURCE_IP_FIELD, "UNKNOWN").strip() for e in failed)
    flagged = {ip: count for ip, count in ip_counts.items() if count > threshold}

    print(f"\nIPs with more than {threshold} failed logons:")
    if not flagged:
        print("  None found.")
    for ip, count in sorted(flagged.items(), key=lambda x: x[1], reverse=True):
        print(f"  {ip}: {count} failed logons")
    return flagged


def count_failed_logons_by_ip(events, top_n=5):
    """Count failed logons per SourceIP, print the top N highest to lowest."""
    failed = filter_by_field(events, EVENTID_FIELD, "4625")
    ip_counts = Counter(e.get(SOURCE_IP_FIELD, "UNKNOWN").strip() for e in failed)

    print(f"\nTop {top_n} source IPs by failed logon count:")
    for ip, count in ip_counts.most_common(top_n):
        print(f"  {ip}: {count}")
    return ip_counts.most_common(top_n)


def find_powershell_mimikatz_process_creation(events):
    """List every 4688 (process creation) event where the process name
    contains 'powershell' or 'mimikatz'."""
    process_events = filter_by_field(events, EVENTID_FIELD, "4688")
    matches = [
        e for e in process_events
        if "powershell" in e.get(PROCESS_NAME_FIELD, "").lower()
        or "mimikatz" in e.get(PROCESS_NAME_FIELD, "").lower()
    ]
    print(f"\n{len(matches)} process-creation (4688) events matching PowerShell/Mimikatz:\n")
    print_events(matches)
    return matches


def flag_suspicious_tools(events, tools=None):
    """Flag any event whose process/description field matches a known
    suspicious tool name (powershell, mimikatz, psexec, rundll32, ...)."""
    tools = tools or SUSPICIOUS_TOOLS
    flagged = [
        e for e in events
        if any(tool in e.get(PROCESS_NAME_FIELD, "").lower() for tool in tools)
    ]
    print(f"\n{len(flagged)} events flagged for suspicious tool names {tools}:\n")
    print_events(flagged)
    return flagged


def main():
    filepath = input("Path to CSV file: ").strip()
    events = load_events(filepath)

    if not events:
        print("No rows found in that file.")
        return

    print(f"\nLoaded {len(events)} events.")
    print(f"Columns found: {list(events[0].keys())}")
    print(f"(Currently configured field names -> EventID: '{EVENTID_FIELD}', "
          f"SourceIP: '{SOURCE_IP_FIELD}', Process/Description: '{PROCESS_NAME_FIELD}')\n")

    menu = """
1) Count events by field
2) Filter events by exact match
3) Filter events by keyword
4) Filter events by EventID
5) Generate security report (CSV) of critical security-related events
6) Print all failed logon (4625) events
7) Flag IPs with more than 5 failed logons
8) Count failed logons per SourceIP (top 5)
9) List 4688 process creation events matching PowerShell/Mimikatz
10) Flag suspicious tool names (powershell, mimikatz, psexec, rundll32)
11) Identify IPs/usernames with unusually high failed logons
12) Quit
"""

    while True:
        print(menu)
        choice = input("Choose an option: ").strip()

        if choice == "1":
            field = input("Field to count by (e.g. EventID): ").strip()
            counts = count_by_field(events, field)
            print(f"\nTop values for '{field}':")
            for value, count in counts.most_common(20):
                print(f"  {value}: {count}")

        elif choice == "2":
            field = input("Field name: ").strip()
            value = input("Exact value to match: ").strip()
            results = filter_by_field(events, field, value)
            print(f"\n{len(results)} matching events\n")
            print_events(results, limit=5)

        elif choice == "3":
            field = input("Field name: ").strip()
            keyword = input("Keyword to search for: ").strip()
            results = filter_contains(events, field, keyword)
            print(f"\n{len(results)} matching events\n")
            print_events(results, limit=5)

        elif choice == "4":
            event_id = input("EventID to filter by (e.g. 4625): ").strip()
            filter_by_eventid(events, event_id)

        elif choice == "5":
            generate_security_report(events)

        elif choice == "6":
            print_failed_logons(events)

        elif choice == "7":
            find_bruteforce_ips(events, threshold=5)

        elif choice == "8":
            count_failed_logons_by_ip(events, top_n=5)

        elif choice == "9":
            find_powershell_mimikatz_process_creation(events)

        elif choice == "10":
            flag_suspicious_tools(events)

        elif choice == "11":
            find_anomalous_failed_logon_sources(events)

        elif choice == "12":
            print("Goodbye.")
            break

        else:
            print("Invalid option, try again.")
            continue

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()