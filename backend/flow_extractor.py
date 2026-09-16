"""
Extracts flow-level features from a pcap file using tshark, in the schema:
bytes_sent, bytes_received, duration, port, protocol_type, service, flag

This aggregates raw packets into bidirectional flows keyed by the 5-tuple
(src ip/port, dst ip/port, protocol), the same way NetFlow/Zeek conn logs do.
"""
import subprocess
import io
import pandas as pd

FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "ip.proto", "frame.len",
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
]

PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

SERVICE_MAP = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    123: "ntp", 143: "imap", 161: "snmp", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 8080: "http_proxy",
}


def _run_tshark(pcap_path: str) -> pd.DataFrame:
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-E", "header=y",
           "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    if not result.stdout.strip():
        return pd.DataFrame(columns=FIELDS)
    return pd.read_csv(io.StringIO(result.stdout))


def _flow_key(row):
    sport = row["sport"]
    dport = row["dport"]
    a = (row["ip.src"], sport)
    b = (row["ip.dst"], dport)
    lo, hi = sorted([a, b])
    return (lo, hi, row["proto"])


def _classify_flag(flags: pd.DataFrame) -> str:
    """Rough approximation of NSL-KDD-style connection flags from TCP flag counts."""
    has_syn = flags["tcp.flags.syn"].fillna(0).sum() > 0
    has_ack = flags["tcp.flags.ack"].fillna(0).sum() > 0
    has_fin = flags["tcp.flags.fin"].fillna(0).sum() > 0
    has_rst = flags["tcp.flags.reset"].fillna(0).sum() > 0

    if has_rst and not has_fin:
        return "REJ" if len(flags) <= 2 else "RSTO"
    if has_fin:
        return "SF"
    if has_syn and not has_ack:
        return "S0"
    if has_syn and has_ack:
        return "S1"
    return "OTH"


def extract_flows(pcap_path: str) -> pd.DataFrame:
    df = _run_tshark(pcap_path)
    if df.empty:
        return pd.DataFrame(columns=[
            "src_ip", "dst_ip", "duration", "bytes_sent", "bytes_received",
            "port", "protocol_type", "service", "flag",
        ])

    df["sport"] = df["tcp.srcport"].combine_first(df.get("udp.srcport"))
    df["dport"] = df["tcp.dstport"].combine_first(df.get("udp.dstport"))
    df["proto"] = df["ip.proto"]
    df = df.dropna(subset=["ip.src", "ip.dst", "proto"])

    df["flow_key"] = df.apply(_flow_key, axis=1)

    rows = []
    for key, group in df.groupby("flow_key"):
        group = group.sort_values("frame.time_epoch")
        first = group.iloc[0]
        orig_ip, orig_port = first["ip.src"], first["sport"]

        is_orig = (group["ip.src"] == orig_ip) & (group["sport"] == orig_port)
        bytes_sent = group.loc[is_orig, "frame.len"].sum()
        bytes_received = group.loc[~is_orig, "frame.len"].sum()

        duration = float(group["frame.time_epoch"].max() - group["frame.time_epoch"].min())
        proto_num = int(first["proto"])
        protocol_type = PROTO_MAP.get(proto_num, "other")

        resp_port = first["dport"] if pd.notna(first["dport"]) else None
        service = SERVICE_MAP.get(int(resp_port), "other") if resp_port is not None else "other"

        if protocol_type == "tcp":
            flag = _classify_flag(group[["tcp.flags.syn", "tcp.flags.ack",
                                          "tcp.flags.fin", "tcp.flags.reset"]])
        else:
            flag = "SF"

        rows.append({
            "src_ip": orig_ip,
            "dst_ip": first["ip.dst"] if first["ip.dst"] != orig_ip else first["ip.src"],
            "duration": round(duration, 4),
            "bytes_sent": int(bytes_sent),
            "bytes_received": int(bytes_received),
            "port": int(resp_port) if resp_port is not None else 0,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
        })

    return pd.DataFrame(rows)
