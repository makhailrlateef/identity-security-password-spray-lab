"""Offline password spray detector. Standard library only; synthetic lab data."""
import argparse
import csv
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED = {'timestamp', 'user', 'ip_address', 'result'}


def read_events(path):
    events = []
    with Path(path).open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        if not REQUIRED.issubset(reader.fieldnames or []):
            raise ValueError('CSV needs timestamp,user,ip_address,result headers')
        for line, row in enumerate(reader, 2):
            try:
                event = {key: row[key].strip() for key in REQUIRED}
                time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                if time.tzinfo is None:
                    raise ValueError('timestamp needs a timezone, such as Z or +00:00')
                event['time'] = time.astimezone(timezone.utc)
                event['ip_address'] = str(ipaddress.ip_address(event['ip_address']))
                event['user'] = event['user'].lower()
                event['result'] = event['result'].lower()
                if not event['user'] or event['result'] not in {'success', 'failure'}:
                    raise ValueError('user is required; result must be success or failure')
                events.append(event)
            except (ValueError, AttributeError, KeyError) as exc:
                raise ValueError(f'CSV line {line}: {exc}') from exc
    return events


def detect(events, window_minutes=10, min_users=3):
    """Return the first qualifying window per IP; endpoints are inclusive."""
    if window_minutes < 1 or min_users < 2:
        raise ValueError('window must be >= 1 minute and min-users must be >= 2')
    groups = defaultdict(list)
    for event in events:
        if event['result'] == 'failure':
            groups[event['ip_address']].append(event)
    alerts = []
    for ip, attempts in sorted(groups.items()):
        attempts.sort(key=lambda event: event['time'])
        left = 0
        for right, current in enumerate(attempts):
            while current['time'] - attempts[left]['time'] > timedelta(minutes=window_minutes):
                left += 1
            window = attempts[left:right + 1]
            users = sorted({event['user'] for event in window})
            if len(users) >= min_users:
                alerts.append({
                    'rule': 'Possible password spray',
                    'source_ip': ip,
                    'first_seen_utc': window[0]['time'].isoformat(),
                    'last_seen_utc': current['time'].isoformat(),
                    'distinct_users': len(users),
                    'failed_attempts': len(window),
                    'users': users,
                })
                break
    return alerts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--window-minutes', type=int, default=10)
    parser.add_argument('--min-users', type=int, default=3)
    parser.add_argument('--output', type=Path, help='Optional JSON evidence file')
    args = parser.parse_args()
    try:
        alerts = detect(read_events(args.input), args.window_minutes, args.min_users)
        report = json.dumps(alerts, indent=2) + '\n'
        if args.output:
            args.output.write_text(report, encoding='utf-8')
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Error: {exc}\n')
    print(report, end='')


if __name__ == '__main__':
    main()
