#!/usr/bin/env python3
import argparse
import bisect
import json
import math
import re
from collections import Counter
from pathlib import Path

# candump normally separates the interface and arbitration ID with a space
# (``can0 123#AABB``). Older logs produced by this project use ``can0#123#AABB``.
# Accept both forms so a normal SocketCAN capture is not rejected as CSV.
CANDUMP=re.compile(
    r"^\s*\((?P<ts>[0-9]+(?:\.[0-9]+)?)\)\s+"
    r"[^#\s]+(?:\s+|#)(?P<id>[0-9A-Fa-f]+)"
    r"#(?P<data>[0-9A-Fa-f]*)\s*$"
)
# ``candump`` without ``-L`` prints the payload as a DLC followed by
# space-separated bytes, for example ``(1.0) can0 123 [2] AA BB``.  This is
# the default format on many SocketCAN installations and must be handled in
# addition to the compact ``123#AABB`` form above.
CANDUMP_VERBOSE=re.compile(
    r"^\s*\((?P<ts>[0-9]+(?:\.[0-9]+)?)\)\s+"
    r"[^#\s]+\s+(?P<id>[0-9A-Fa-f]+)\s+"
    r"\[(?P<length>[0-9]+)\]"
    r"(?:\s+(?P<data>(?:[0-9A-Fa-f]{2})(?:\s+[0-9A-Fa-f]{2})*))?\s*$"
)
MAX_CAN_ID = 0x1FFFFFFF

def parse_lines(lines):
    frames=[]
    for line_no,raw in enumerate(lines,1):
        line=raw.strip()
        if not line: continue
        match=CANDUMP.match(line)
        verbose_match=CANDUMP_VERBOSE.match(line)
        if verbose_match:
            timestamp=float(verbose_match.group("ts")); frame_id=int(verbose_match.group("id"),16)
            declared_length=int(verbose_match.group("length")); data="".join((verbose_match.group("data") or "").split())
            if len(data)//2 != declared_length:
                raise ValueError(f"line {line_no}: declared DLC does not match payload")
            if declared_length > 64:
                raise ValueError(f"line {line_no}: declared DLC exceeds 64-byte CAN payload")
        elif match:
            timestamp=float(match.group("ts")); frame_id=int(match.group("id"),16); data=match.group("data") or ""
        else:
            parts=[part.strip() for part in line.split(",")]
            if len(parts)!=3: raise ValueError(f"line {line_no}: expected candump or timestamp,id,data")
            timestamp=float(parts[0]); frame_id=int(parts[1],0); data=parts[2].replace(" ","")
        # ``float`` accepts NaN and infinities in CSV input.  Those values
        # break timestamp ordering and cause ``json.dumps`` to emit
        # non-standard JSON (NaN/Infinity), so reject them at the parser
        # boundary before they can corrupt burst analysis.
        if not math.isfinite(timestamp):
            raise ValueError(f"line {line_no}: timestamp must be finite")
        # CAN arbitration IDs are at most 29 bits (extended frame format).
        # Accepting larger or negative values silently turns malformed logs
        # into plausible-looking reports and can corrupt ID-based triage.
        if not 0 <= frame_id <= MAX_CAN_ID:
            raise ValueError(f"line {line_no}: invalid CAN arbitration ID")
        if len(data)%2 or any(c not in "0123456789abcdefABCDEF" for c in data) or len(data)>128: raise ValueError(f"line {line_no}: invalid data bytes")
        frames.append({"timestamp":timestamp,"id":frame_id,"data":data.upper()})
    return frames

def inspect(frames,known_ids=(),burst_threshold=100,window_seconds=1.0):
    # A negative threshold makes every non-empty window a "burst", producing
    # false incident reports when a CLI typo or untrusted configuration slips
    # through.  Thresholds count frames and therefore must be non-negative.
    if burst_threshold < 0:
        raise ValueError("burst_threshold must be non-negative")
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
