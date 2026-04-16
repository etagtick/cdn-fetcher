#!/usr/bin/env python3
"""
GitHub Actions equivalent of vxc poll_loop.
Fetches CBOE delayed quotes for _SPX, SPY, _VIX and persists in V2 binary format
compatible with the Rust vxc server (data/chain/{ROOT}/*.bin).

Dedup strategy: compute a fingerprint of the options payload and skip writing
if it matches the fingerprint of the latest .bin on disk.
"""

import hashlib
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── Config ──
TICKERS = ["_SPX", "SPY", "_VIX"]
BASE_URL = "https://cdn.cboe.com/api/global/delayed_quotes/options/{}.json"
HEADERS = {"User-Agent": "Mozilla/5.0"}
DATA_ROOT = Path("data/chain")

# ── V2 binary format constants (match Rust byte-for-byte) ──
V2_MAGIC = b"VXC2"
V2_HEADER_BYTES = 32
V2_EXP_BYTES = 12
V2_ROOT_BYTES = 8
V2_REC_BYTES = 16


# ── Date helpers (match Rust ymd_to_days / today_yymmdd) ──

def ymd_to_days(y, m, d):
    if m <= 2:
        y -= 1
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    mm = m - 3 if m > 2 else m + 9
    doy = (153 * mm + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def today_yymmdd():
    now = datetime.now(timezone.utc)
    return (now.year % 100) * 10000 + now.month * 100 + now.day


def dte(expiry, today):
    ey = 2000 + expiry // 10000
    em = (expiry // 100) % 100
    ed = expiry % 100
    ty = 2000 + today // 10000
    tm = (today // 100) % 100
    td = today % 100
    return ymd_to_days(ey, em, ed) - ymd_to_days(ty, tm, td)


def trading_dte(expiry, today):
    ey = 2000 + expiry // 10000
    em = (expiry // 100) % 100
    ed = expiry % 100
    ty = 2000 + today // 10000
    tm = (today // 100) % 100
    td = today % 100
    exp_d = ymd_to_days(ey, em, ed)
    today_d = ymd_to_days(ty, tm, td)
    if exp_d <= today_d:
        return 0
    count = 0
    d = today_d + 1
    while d <= exp_d:
        weekday = (d + 3) % 7  # 0=Mon..6=Sun
        if weekday < 5:
            count += 1
        d += 1
    return count


def ts_string_to_epoch(ts):
    """'YYYY-MM-DD HH:MM:SS' → unix epoch seconds."""
    try:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        return int(dt.replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return 0


def ts_to_filename(ts):
    """'YYYY-MM-DD HH:MM:SS' → 'YYYYMMDD_HHMMSS.bin'."""
    return ts.replace("-", "").replace(" ", "_").replace(":", "") + ".bin"


# ── Parse CBOE option symbol (matches Rust fetch_chain) ──

def parse_chain(payload):
    """CBOE JSON → dict {current_price, timestamp, options:[...]}."""
    data = payload["data"]
    current_price = data["current_price"]
    ts = payload["timestamp"]
    today = today_yymmdd()

    parsed = []
    for opt in data.get("options", []):
        sym = opt.get("option", "")
        if len(sym) < 15:
            continue

        exp_str = sym[-15:-9]
        right_ch = sym[-9]
        strike_raw = sym[-8:]
        root = sym[:-15].strip()

        if right_ch not in ("C", "P"):
            continue

        try:
            expiry = int(exp_str)
            strike_i = int(strike_raw)
        except ValueError:
            continue

        strike = strike_i / 1000.0
        d = dte(expiry, today)
        if d < 0:
            continue

        iv = opt.get("iv", 0.0) or 0.0
        bid = opt.get("bid", 0.0) or 0.0
        ask = opt.get("ask", 0.0) or 0.0
        delta = opt.get("delta", 0.0) or 0.0

        if iv <= 0.0 and bid <= 0.0 and ask <= 0.0:
            continue

        # DTE + |delta| gate (keeps bid/ask under u16 cents cap $655.35)
        abs_delta = abs(delta)
        if d > 160:
            continue
        elif d >= 100 and abs_delta > 0.65:
            continue
        elif d < 100 and abs_delta > 0.75:
            continue

        td = trading_dte(expiry, today)
        parsed.append({
            "strike": strike,
            "dte": d,
            "tdte": td,
            "exp": exp_str,
            "iv": iv,
            "bid": bid,
            "ask": ask,
            "right": right_ch,
            "oi": int(opt.get("open_interest", 0) or 0),
            "volume": int(opt.get("volume", 0) or 0),
            "root": root,
        })

    return {"current_price": current_price, "timestamp": ts, "options": parsed}


# ── Fingerprint (content-based dedup) ──

def options_fingerprint(options):
    """
    Stable hash of options content, quantised to V2 precision so that a fingerprint
    computed on a fresh parse matches one recomputed after a V2 round-trip.
    Sort-independent.
    """
    h = hashlib.blake2b(digest_size=16)
    for o in sorted(options, key=lambda x: (x["exp"], x["right"], x["strike"])):
        # Quantise to V2 precision: strike cents, iv×10000, price cents, oi//100, vol//100
        strike_c = round(o["strike"] * 100)
        iv_q = round(o["iv"] * 10000)
        bid_c = round(o["bid"] * 100)
        ask_c = round(o["ask"] * 100)
        oi_h = o["oi"] // 100
        vol_h = o["volume"] // 100
        h.update(
            f"{o['exp']}{o['right']}{strike_c}"
            f"{iv_q}{bid_c}{ask_c}{oi_h}{vol_h}".encode()
        )
    return h.hexdigest()


# ── V2 binary reader (for fingerprint of latest .bin) ──

def read_v2_options(path):
    """Read a V2 .bin and return list of option dicts. None if invalid."""
    data = path.read_bytes()
    if len(data) < V2_HEADER_BYTES or data[:4] != V2_MAGIC:
        return None

    n_exps = struct.unpack_from("<H", data, 22)[0]
    n_roots = data[24]
    n_options = struct.unpack_from("<I", data, 28)[0]

    exp_off = V2_HEADER_BYTES
    root_off = exp_off + n_exps * V2_EXP_BYTES
    rec_off = root_off + n_roots * V2_ROOT_BYTES

    if len(data) < rec_off + n_options * V2_REC_BYTES:
        return None

    exps = []
    for i in range(n_exps):
        o = exp_off + i * V2_EXP_BYTES
        ym, _d, _td, _fwd = struct.unpack_from("<Ihhf", data, o)
        yy = (ym // 10000) % 100
        mm = (ym // 100) % 100
        dd = ym % 100
        exps.append(f"{yy:02d}{mm:02d}{dd:02d}")

    roots = []
    for i in range(n_roots):
        o = root_off + i * V2_ROOT_BYTES
        name = bytes(data[o:o+8]).rstrip(b"\x00").decode("ascii", errors="ignore")
        roots.append(name)

    options = []
    for i in range(n_options):
        o = rec_off + i * V2_REC_BYTES
        strike_c, meta, iv_q, bid_c, ask_c, oi_h, vol_h = \
            struct.unpack_from("<IHHHHHH", data, o)

        ri = (meta >> 14) & 0x3
        right = "C" if ((meta >> 13) & 0x1) == 0 else "P"
        ei = meta & 0x1FFF

        options.append({
            "strike": strike_c / 100.0,
            "exp": exps[ei] if ei < len(exps) else "",
            "right": right,
            "iv": iv_q / 10000.0,
            "bid": bid_c / 100.0,
            "ask": ask_c / 100.0,
            "oi": oi_h * 100,
            "volume": vol_h * 100,
            "root": roots[ri] if ri < len(roots) else "",
        })
    return options


def latest_fingerprint(root):
    """Fingerprint of the newest .bin in data/chain/{root}/, or None."""
    folder = DATA_ROOT / root
    if not folder.exists():
        return None
    bins = sorted(p for p in folder.glob("*.bin") if not p.name.startswith("."))
    if not bins:
        return None
    options = read_v2_options(bins[-1])
    if options is None:
        return None
    return options_fingerprint(options)


# ── V2 binary writer (byte-for-byte match with Rust persist_chain_v2) ──

def write_chain_v2(root, chain):
    folder = DATA_ROOT / root
    folder.mkdir(parents=True, exist_ok=True)
    fname = ts_to_filename(chain["timestamp"])
    path = folder / fname

    options = chain["options"]
    if not options:
        print(f"  [{root}] no options to persist")
        return None

    # Build exp table (dedup, sorted by yyyymmdd like Rust BTreeMap)
    exp_map = {}
    for o in options:
        yy = int(o["exp"][0:2])
        mm = int(o["exp"][2:4])
        dd = int(o["exp"][4:6])
        yyyymmdd = 20000000 + yy * 10000 + mm * 100 + dd
        exp_map[yyyymmdd] = (o["dte"], o["tdte"])

    exp_list = sorted(exp_map.items())  # [(yyyymmdd, (dte, tdte))]
    exp_idx = {ym: i for i, (ym, _) in enumerate(exp_list)}

    # Build root table (dedup, first-seen order like Rust)
    root_list = []
    for o in options:
        if o["root"] not in root_list:
            root_list.append(o["root"])
    root_idx = {r: i for i, r in enumerate(root_list)}

    n_exps = len(exp_list)
    n_roots = len(root_list)
    n_options = len(options)

    ts_epoch = ts_string_to_epoch(chain["timestamp"])
    und_c = int(chain["current_price"] * 100)
    fwd = float(chain["current_price"])

    buf = bytearray()

    # Header (32 bytes)
    buf += V2_MAGIC                                     # 4
    buf += struct.pack("<I", 2)                         # 4 version
    buf += struct.pack("<Q", ts_epoch)                  # 8
    buf += struct.pack("<I", und_c)                     # 4
    buf += struct.pack("<H", 0)                         # 2 rate_bp
    buf += struct.pack("<H", n_exps)                    # 2
    buf += struct.pack("<B", n_roots)                   # 1
    buf += b"\x00\x00\x00"                              # 3 pad
    buf += struct.pack("<I", n_options)                 # 4

    # Exp table (12 bytes each)
    for ym, (d, td) in exp_list:
        buf += struct.pack("<Ihhf", ym, d, td, fwd)

    # Root table (8 bytes each, null-padded)
    for r in root_list:
        name = r.encode("ascii")[:8]
        buf += name + b"\x00" * (8 - len(name))

    # Records (16 bytes each)
    for o in options:
        yy = int(o["exp"][0:2])
        mm = int(o["exp"][2:4])
        dd = int(o["exp"][4:6])
        yyyymmdd = 20000000 + yy * 10000 + mm * 100 + dd
        ei = exp_idx[yyyymmdd]
        ri = root_idx[o["root"]]
        right_bit = 0 if o["right"] == "C" else 1
        meta = ((ri & 0x3) << 14) | ((right_bit & 0x1) << 13) | (ei & 0x1FFF)

        strike_c = min(max(round(o["strike"] * 100), 0), 0xFFFFFFFF)
        iv_q = min(max(round(o["iv"] * 10000), 0), 0xFFFF)
        bid_c = min(max(round(o["bid"] * 100), 0), 0xFFFF)
        ask_c = min(max(round(o["ask"] * 100), 0), 0xFFFF)
        oi_h = min(o["oi"] // 100, 0xFFFF)
        vol_h = min(o["volume"] // 100, 0xFFFF)

        buf += struct.pack("<IHHHHHH", strike_c, meta, iv_q, bid_c, ask_c, oi_h, vol_h)

    # Atomic write
    tmp = folder / f".{fname}.tmp"
    tmp.write_bytes(bytes(buf))
    tmp.replace(path)
    print(f"  [{root}] persisted {fname} → {n_options} records ({len(buf)//1024} KB)")
    return path


# ── Fetch ──

def fetch_one(ticker):
    url = BASE_URL.format(ticker)
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()


# ── Main ──

def main():
    errors = []
    for ticker in TICKERS:
        root = ticker.lstrip("_")
        prev_fp = latest_fingerprint(root)
        try:
            payload = fetch_one(ticker)
            chain = parse_chain(payload)

            if not chain["options"]:
                print(f"  {ticker} no options after filter, skip")
                continue

            current_fp = options_fingerprint(chain["options"])
            if current_fp == prev_fp:
                print(f"  {ticker} fingerprint unchanged, skip "
                      f"(ts={chain['timestamp']})")
                continue

            write_chain_v2(root, chain)
            print(f"  {ticker} → {len(chain['options'])} options, "
                  f"und={chain['current_price']:.2f} ts={chain['timestamp']}")
        except Exception as e:
            print(f"  {ticker} ERROR: {e}", file=sys.stderr)
            errors.append(ticker)

    if errors and len(errors) == len(TICKERS):
        sys.exit(f"All fetches failed: {errors}")


if __name__ == "__main__":
    main()
