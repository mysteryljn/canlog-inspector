#!/usr/bin/env python3
import argparse
import bisect
import json
import re
from collections import Counter
from pathlib import Path

# candump normally separates the interface and arbitration ID with a space
# (``can0 123#AABB``). Older logs produced by this project use ``can0#123#AABB``.
# Accept both forms so a normal SocketCAN capture is not rejected as CSV.
CANDUMP=re.compile(
    r"^\s*\((?P<ts>[0-9]+(?:\.[0-9]+)?)\)\s+"
    r"[^#\s]+(?:\s+|#)(?P<id>[0-9A-Fa-f]+)"
    r"(?:#(?P<data>[0-9A-Fa-f]*))?\s*$"
)

def parse_lines(lines):
    frames=[]
    for line_no,raw in enumerate(lines,1):
        line=raw.strip()
        if not line: continue
        match=CANDUMP.match(line)
        if match:
            timestamp=float(match.group("ts")); frame_id=int(match.group("id"),16); data=match.group("data") or ""
        else:
            parts=[part.strip() for part in line.split(",")]
            if len(parts)!=3: raise ValueError(f"line {line_no}: expected candump or timestamp,id,data")
            timestamp=float(parts[0]); frame_id=int(parts[1],0); data=parts[2].replace(" ","")
        if len(data)%2 or any(c not in "0123456789abcdefABCDEF" for c in data) or len(data)>128: raise ValueError(f"line {line_no}: invalid data bytes")
        frames.append({"timestamp":timestamp,"id":frame_id,"data":data.upper()})
    return frames

def inspect(frames,known_ids=(),burst_threshold=100,window_seconds=1.0):
    known=set(known_ids); counts=Counter(frame["id"] for frame in frames)
    unknown=sorted({frame["id"] for frame in frames if known and frame["id"] not in known}); bursts=[]
    # Logs can be merged from multiple interfaces and arrive out of order.  Use
    # the timestamps, rather than the input order, when evaluating a time
    # window.  The old suffix count also included frames *before* the current
    # frame's timestamp, producing false burst reports for unsorted logs.
    timestamps=sorted(frame["timestamp"] for frame in frames)
    for i,start in enumerate(timestamps):
        end=start+window_seconds
        right=bisect.bisect_right(timestamps,end)
        count=right-i
        if count>burst_threshold:
            bursts.append({"start":start,"count":count}); break
    return {"frames":len(frames),"ids":{str(k):v for k,v in sorted(counts.items())},"unknown_ids":unknown,"bursts":bursts,"empty_payloads":sum(1 for frame in frames if not frame["data"])}

def main(argv=None):
    parser=argparse.ArgumentParser(description="Inspect an offline CAN log"); parser.add_argument("log",type=Path); parser.add_argument("--known-id",action="append",default=[],type=lambda value:int(value,0)); parser.add_argument("--burst-threshold",type=int,default=100); args=parser.parse_args(argv)
    try: report=inspect(parse_lines(args.log.read_text(encoding="utf-8").splitlines()),args.known_id,args.burst_threshold)
    except (OSError,ValueError) as exc: print(f"error: {exc}"); return 2
    print(json.dumps(report,indent=2)); return 0

if __name__=="__main__": raise SystemExit(main())
