#!/usr/bin/env python3
import argparse
import json
import re
from collections import Counter
from pathlib import Path

CANDUMP=re.compile(r"^\s*\((?P<ts>[0-9.]+)\)\s+[^#\s]+#(?P<id>[0-9A-Fa-f]+)(?:#(?P<data>[0-9A-Fa-f]*))?\s*$")

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
    for i,frame in enumerate(frames):
        end=frame["timestamp"]+window_seconds; count=sum(1 for candidate in frames[i:] if candidate["timestamp"]<=end)
        if count>burst_threshold: bursts.append({"start":frame["timestamp"],"count":count}); break
    return {"frames":len(frames),"ids":{str(k):v for k,v in sorted(counts.items())},"unknown_ids":unknown,"bursts":bursts,"empty_payloads":sum(1 for frame in frames if not frame["data"])}

def main(argv=None):
    parser=argparse.ArgumentParser(description="Inspect an offline CAN log"); parser.add_argument("log",type=Path); parser.add_argument("--known-id",action="append",default=[],type=lambda value:int(value,0)); parser.add_argument("--burst-threshold",type=int,default=100); args=parser.parse_args(argv)
    try: report=inspect(parse_lines(args.log.read_text(encoding="utf-8").splitlines()),args.known_id,args.burst_threshold)
    except (OSError,ValueError) as exc: print(f"error: {exc}"); return 2
    print(json.dumps(report,indent=2)); return 0

if __name__=="__main__": raise SystemExit(main())
