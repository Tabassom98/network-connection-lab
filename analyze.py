"""Analyze a small normalized JSONL network connection export offline."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys


def load(path):
    events=[]
    seen=set()
    for number,line in enumerate(Path(path).read_text(encoding='utf-8').splitlines(),1):
        if not line.strip(): continue
        try:
            row=json.loads(line)
            if not isinstance(row,dict): raise ValueError('expected object')
            if not isinstance(row.get('id'),str) or not row['id'].strip() or row['id'] in seen:
                raise ValueError('id must be nonempty and unique')
            stamp=datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
            if stamp.tzinfo is None: raise ValueError('timestamp needs timezone')
            for field in ('src','dst'): row[field]=str(ipaddress.ip_address(row[field]))
            for field in ('dst_port','bytes_out'):
                if type(row.get(field)) is not int: raise ValueError(field+' must be integer')
            if not 1 <= row['dst_port'] <= 65535 or row['bytes_out'] < 0: raise ValueError('invalid port or byte count')
            row['time']=stamp.astimezone(timezone.utc).timestamp()
            events.append(row)
            seen.add(row['id'])
        except (ValueError,KeyError,TypeError,AttributeError) as exc:
            raise ValueError(f'line {number}: {exc}') from exc
    return sorted(events,key=lambda e:(e['time'],e['id']))


def analyze(events, min_ports=5, window=60, byte_threshold=10000000):
    for value in (min_ports,window,byte_threshold):
        if type(value) is not int or value < 1: raise ValueError('thresholds must be positive integers')
    recent=defaultdict(list)
    totals=defaultdict(int)
    ids=defaultdict(list)
    emitted=set()
    findings=[]
    for row in sorted(events,key=lambda e:(e['time'],e['id'])):
        pair=(row['src'],row['dst'])
        recent[pair]=[r for r in recent[pair] if r['time'] >= row['time']-window]
        recent[pair].append(row)
        ports=sorted({r['dst_port'] for r in recent[pair]})
        if len(ports)>=min_ports and pair not in emitted:
            findings.append(dict(rule='NET-001',src=pair[0],dst=pair[1],ports=ports,
                                 evidence=[r['id'] for r in recent[pair]]))
            emitted.add(pair)
        totals[pair]+=row['bytes_out']
        ids[pair].append(row['id'])
    for pair,total in sorted(totals.items()):
        if total>=byte_threshold:
            findings.append(dict(rule='NET-002',src=pair[0],dst=pair[1],bytes_out=total,evidence=ids[pair]))
    return findings


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    args=parser.parse_args(argv)
    try: result=analyze(load(args.input))
    except (OSError,ValueError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 2
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__=='__main__': raise SystemExit(main())
