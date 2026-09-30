# Windows Event Log Parser

A command-line Python tool for SOC-style triage of Windows Security Event Log exports. It loads a CSV of events, then lets you count, filter, and flag security-relevant activity from a simple menu. It uses only the Python standard library, so there is nothing to install.

## What it does

- Filters events by any field, by keyword, or by Event ID
- Builds a CSV report of security-relevant Event IDs such as 4624, 4625, 4688, 4720, 4728, 4740, 7045, and 1102 (audit log cleared)
- Counts failed logons (4625) per source IP and flags likely brute-force sources
- Uses a mean plus standard deviation threshold to spot unusual IPs and usernames in failed logons, so the cutoff adapts to each log instead of relying on one fixed number
- Flags process activity involving tools attackers commonly abuse, including PowerShell, Mimikatz, PsExec, and rundll32

## Run it

    python log_parser.py

Enter the path to a CSV when prompted, for example `sample-data/simulated_windows_events.csv`, then choose options from the menu. The security report is saved to your Desktop.

If your CSV uses different column names, edit the field names near the top of the script. The script prints the columns it finds when it loads a file to make this easy.

## Sample data

`sample-data/simulated_windows_events.csv` holds 69 simulated events (no real systems or people). It includes a brute-force pattern of 26 failed logons from one external IP against a single account, followed by suspicious process activity, a new account being created and added to a group, a service install, and the audit log being cleared.

`sample-data/security_report.csv` is the report the tool produced from that data.

## What I learned

- Which Windows Event IDs matter most for triage and what each one means
- Parsing and filtering CSV data with `csv.DictReader` and `collections.Counter`
- Why a fixed alert threshold breaks down across different log sizes, and how a statistical baseline helps

## How this was built

I built this with help from an AI assistant (Claude) as a learning aid, then tested and adjusted it against the sample data.
