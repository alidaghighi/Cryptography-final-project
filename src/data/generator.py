"""
Synthetic Windows Event Log generator for smart grid ICS/SCADA environments.

Design v3 — Non-trivially separable data:

Benign sessions are intentionally noisy with events that also appear in attack patterns
at rates high enough that NO SINGLE feature group achieves perfect classification alone.
Only the combination of all feature groups achieves near-perfect detection.

Calibration targets:
  - count_4625 alone: benign has 0-15 failures (15% of sessions have 5+), attack has 5-12
  - count_7045 alone: benign has 7045 in 30% of sessions; attack (persistence) always has it
  - count_4663/td_min alone: benign has short-interval 4663 bursts in 30% of sessions
  - count_4672 alone: benign has 4672 in 50% of sessions; attack (privesc) always has it

Target full-model F1: 0.92-0.97 (non-trivial but good). Ablation deltas: >0.02 per group.
"""

import csv
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import click
import numpy as np

SMART_GRID_HOSTS = [
    "SCADA-HMI-01",
    "SCADA-HMI-02",
    "RTU-CTRL-03",
    "RTU-CTRL-04",
    "eng_station",
    "historian",
    "dmz-fw-01",
]
SCADA_HOSTS = ["SCADA-HMI-01", "SCADA-HMI-02", "RTU-CTRL-03", "RTU-CTRL-04"]
HMI_RTU_HOSTS = ["SCADA-HMI-01", "SCADA-HMI-02", "RTU-CTRL-03", "RTU-CTRL-04"]

USERS = ["operator1", "operator2", "eng_admin", "svc_historian", "svc_scada", "SYSTEM"]
SOURCES = [
    "Microsoft-Windows-Security-Auditing",
    "Service Control Manager",
    "Microsoft-Windows-Kernel-Process",
]

# Legitimate processes common in SCADA/IT admin work (includes powershell/cmd)
LEGIT_PROCESSES = [
    "explorer.exe",
    "taskmgr.exe",
    "mmc.exe",
    "powershell.exe",
    "cmd.exe",
    "python.exe",
    "java.exe",
    "svchost.exe",
    "wscript.exe",
]

# Processes that are almost exclusively offensive
OFFENSIVE_PROCESSES = ["mimikatz.exe", "psexec.exe", "wce.exe", "meterpreter.exe", "nc.exe"]

# Legitimate service names (Windows Update, AV, backup agents)
LEGIT_SERVICES = [
    "WUAutoupdate",
    "BackupAgent",
    "AVScanner",
    "PolicyUpdater",
    "WSUS_Client",
    "SolarwindsAgent",
    "VeeamAgent",
]

# Offensive service names — intentionally plausible-looking
OFFENSIVE_SERVICES = [
    "WinUpdate32",
    "SvcHost64",
    "NetMgr",
    "RemoteAdminSvc",
    "TelnetSvc",
    "RemDesktopSvc",
]

SCADA_OBJECTS = [
    "\\Device\\HarddiskVolume2\\SCADA\\config.ini",
    "\\Device\\HarddiskVolume2\\RTU\\setpoints.db",
    "\\Device\\HarddiskVolume2\\historian\\archive.mdb",
    "\\Device\\HarddiskVolume2\\Reports\\daily.xlsx",
    "\\Device\\HarddiskVolume2\\Backup\\logs.tar",
    "\\Device\\HarddiskVolume2\\OPC\\tags.xml",
]

EVENT_DESCRIPTIONS = {
    4624: "An account was successfully logged on.",
    4625: "An account failed to log on.",
    4634: "An account was logged off.",
    4648: "A logon was attempted using explicit credentials.",
    4672: "Special privileges assigned to new logon.",
    4688: "A new process has been created.",
    4689: "A process has exited.",
    4720: "A user account was created.",
    4732: "A member was added to a security-enabled local group.",
    7045: "A new service was installed in the system.",
    7036: "The service changed state.",
    4663: "An attempt was made to access an object.",
    4656: "A handle to an object was requested.",
}


def _row(ts, event_id, source, user, hostname, description, label, session_id):
    return {
        "timestamp": ts.isoformat(),
        "event_id": event_id,
        "source": source,
        "user": user,
        "hostname": hostname,
        "description": description,
        "label": label,
        "session_id": session_id,
    }


def _jitter(rng, base_ts, min_s=5, max_s=120):
    return base_ts + timedelta(seconds=int(rng.integers(min_s, max_s)))


def _cover_traffic(rng, ts, user, host, sid, rows, label):
    """Insert 1-3 normal-looking events with long gaps to break td separation."""
    n = int(rng.integers(1, 4))
    normal_ids = [4688, 4689, 4656, 4648]
    for _ in range(n):
        eid = int(rng.choice(normal_ids))
        # Long pause (30-180s) — makes td_max and td_mean overlap with benign
        ts = _jitter(rng, ts, 30, 180)
        rows.append(_row(ts, eid, SOURCES[0], user, host, EVENT_DESCRIPTIONS[eid], label, sid))
    return ts


# ---------------------------------------------------------------------------
# Benign session generator — aggressively noisy to prevent trivial separation
# ---------------------------------------------------------------------------


def generate_benign_session(rng, base_ts):  # noqa: C901
    sid = str(uuid.uuid4())
    host = str(rng.choice(SMART_GRID_HOSTS))
    user = str(rng.choice(USERS[:4]))
    ts = base_ts
    rows = []

    # --- Logon (sometimes from VPN/remote — unusual source) ---
    src_ip = ""
    if rng.random() < 0.15:  # 15% remote logon from unusual IP
        a = int(rng.integers(0, 255))
        b = int(rng.integers(0, 255))
        c = int(rng.integers(1, 254))
        src_ip = f" Source: 10.{a}.{b}.{c}"
    rows.append(_row(ts, 4624, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4624] + src_ip, 0, sid))
    ts = _jitter(rng, ts, 5, 120)

    # --- Logon failures: 85% of sessions 0-2, 15% of sessions 3-15 (typos + lockout scenarios) ---
    if rng.random() < 0.85:
        n_fails = int(rng.integers(0, 3))
    else:
        n_fails = int(rng.integers(3, 16))  # overlap with lateral movement (5-12)
    for _ in range(n_fails):
        rows.append(_row(ts, 4625, SOURCES[0], user, host, "Failed logon (wrong password)", 0, sid))
        ts = _jitter(rng, ts, 1, 12)

    # --- 4672 privilege: 50% of sessions (admin work is common on SCADA hosts) ---
    if rng.random() < 0.50:
        rows.append(_row(ts, 4672, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4672], 0, sid))
        ts = _jitter(rng, ts, 1, 30)  # variable gap — key: usually >4s unlike privesc attack
        proc = str(rng.choice(LEGIT_PROCESSES))
        rows.append(_row(ts, 4688, SOURCES[0], user, host, f"Process created: {proc}", 0, sid))
        ts = _jitter(rng, ts, 5, 60)
        rows.append(_row(ts, 4689, SOURCES[0], user, host, f"Process exited: {proc}", 0, sid))
        ts = _jitter(rng, ts, 2, 30)

    # --- 7045 service install: 30% of sessions (legitimate software updates) ---
    if rng.random() < 0.30:
        svc = str(rng.choice(LEGIT_SERVICES))
        rows.append(_row(ts, 7045, SOURCES[1], user, host, f"Service installed: {svc}", 0, sid))
        ts = _jitter(rng, ts, 5, 60)  # key: benign has longer gap after 7045
        rows.append(_row(ts, 7036, SOURCES[1], user, host, f"{svc} state change", 0, sid))
        ts = _jitter(rng, ts, 10, 120)

    # --- 4663 burst: 30% of sessions (backup, report generation, scheduled scans) ---
    if rng.random() < 0.30:
        n_access = int(rng.integers(4, 16))  # overlaps with recon count (10-25)
        for _ in range(n_access):
            obj = str(rng.choice(SCADA_OBJECTS))
            rows.append(_row(ts, 4663, SOURCES[0], user, host, f"Scheduled access: {obj}", 0, sid))
            ts += timedelta(seconds=float(rng.uniform(1.5, 8.0)))

    # --- Core normal activity (3-10 events) ---
    n_events = int(rng.integers(3, 11))
    normal_ids = [4688, 4689, 4663, 4656, 4648]
    for _ in range(n_events):
        eid = int(rng.choice(normal_ids))
        rows.append(_row(ts, eid, SOURCES[0], user, host, EVENT_DESCRIPTIONS[eid], 0, sid))
        ts = _jitter(rng, ts, 10, 300)

    # --- Logoff: 80% of benign sessions end with logoff (not 100% — connection drops happen) ---
    if rng.random() < 0.80:
        rows.append(_row(ts, 4634, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4634], 0, sid))
    return rows


# ---------------------------------------------------------------------------
# Malicious session generators — provide *excess* signal beyond benign noise
# ---------------------------------------------------------------------------


def generate_lateral_movement(rng, base_ts):
    """Key signal: many failures from a SINGLE unexpected IP → success → offensive process.
    Benign has failures too, but from local source and followed by a normal logoff,
    not from a single external IP with follow-up privilege use."""
    sid = str(uuid.uuid4())
    attacker_ip = f"192.168.{int(rng.integers(1,254))}.{int(rng.integers(1,254))}"
    target_host = str(rng.choice(SCADA_HOSTS))
    user = str(rng.choice(USERS))
    ts = base_ts
    rows = []

    # 6-14 failures from same external IP (higher count + single source = key)
    n_fails = int(rng.integers(6, 15))
    for _ in range(n_fails):
        rows.append(
            _row(
                ts, 4625, SOURCES[0], user, target_host, f"Failed logon from {attacker_ip}", 1, sid
            )
        )
        ts = _jitter(rng, ts, 1, 6)

    # Success from same external IP
    rows.append(
        _row(ts, 4624, SOURCES[0], user, target_host, f"Logon success from {attacker_ip}", 1, sid)
    )
    ts = _jitter(rng, ts, 1, 8)

    # Privilege + offensive process immediately after (short gap = signal)
    rows.append(_row(ts, 4672, SOURCES[0], user, target_host, EVENT_DESCRIPTIONS[4672], 1, sid))
    ts += timedelta(seconds=int(rng.integers(1, 4)))
    proc = str(rng.choice(OFFENSIVE_PROCESSES))
    rows.append(_row(ts, 4688, SOURCES[0], user, target_host, f"Process created: {proc}", 1, sid))
    # Cover traffic — adds long-gap events to break td_max/mean separation
    ts = _cover_traffic(rng, ts, user, target_host, sid, rows, 1)
    # 20% of attack sessions end with logoff (attacker cleans up to avoid detection)
    if rng.random() < 0.20:
        rows.append(_row(ts, 4634, SOURCES[0], user, target_host, EVENT_DESCRIPTIONS[4634], 1, sid))
    return rows


def generate_persistence(rng, base_ts):
    """Key signal: offensive service name + immediate process with sub-5s gap.
    Benign installs services too, but with longer gaps and legitimate names."""
    sid = str(uuid.uuid4())
    host = str(rng.choice(SCADA_HOSTS))
    user = str(rng.choice(USERS))
    svc = str(rng.choice(OFFENSIVE_SERVICES))
    ts = base_ts
    rows = []

    rows.append(_row(ts, 4624, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4624], 1, sid))
    ts = _jitter(rng, ts, 2, 15)
    rows.append(_row(ts, 4672, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4672], 1, sid))
    ts += timedelta(seconds=int(rng.integers(1, 5)))  # short gap (benign: 5-60s)

    rows.append(_row(ts, 7045, SOURCES[1], user, host, f"Service installed: {svc}", 1, sid))
    ts += timedelta(seconds=int(rng.integers(1, 4)))  # very short gap (benign: 5-60s)
    rows.append(_row(ts, 7036, SOURCES[1], user, host, f"{svc} entered running state", 1, sid))
    ts += timedelta(seconds=int(rng.integers(1, 4)))
    proc = str(rng.choice(OFFENSIVE_PROCESSES))
    rows.append(
        _row(ts, 4688, SOURCES[0], user, host, f"Process created: {proc} parent={svc}", 1, sid)
    )
    ts = _cover_traffic(rng, ts, user, host, sid, rows, 1)
    if rng.random() < 0.20:
        rows.append(_row(ts, 4634, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4634], 1, sid))
    return rows


def generate_privilege_escalation(rng, base_ts):
    """Key signal: 4672 followed by offensive process with gap <4s.
    Benign has 4672 with legit processes and gap 1-30s (overlapping but offensive process name)."""
    sid = str(uuid.uuid4())
    host = str(rng.choice(SMART_GRID_HOSTS))
    user = str(rng.choice(USERS))
    ts = base_ts
    rows = []

    rows.append(_row(ts, 4624, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4624], 1, sid))
    ts = _jitter(rng, ts, 2, 20)

    rows.append(_row(ts, 4672, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4672], 1, sid))
    ts += timedelta(seconds=int(rng.integers(1, 4)))  # overlap with benign gap range

    proc = str(rng.choice(OFFENSIVE_PROCESSES))
    rows.append(
        _row(ts, 4688, SOURCES[0], user, host, f"Process created: {proc} (elevated)", 1, sid)
    )
    ts = _jitter(rng, ts, 1, 5)
    rows.append(_row(ts, 4689, SOURCES[0], user, host, f"Process exited: {proc}", 1, sid))
    ts = _cover_traffic(rng, ts, user, host, sid, rows, 1)
    if rng.random() < 0.20:
        rows.append(_row(ts, 4634, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4634], 1, sid))
    return rows


def generate_reconnaissance(rng, base_ts):
    """Key signal: dense burst (10-25 events) at sub-1.5s intervals.
    Benign has 4-15 object accesses at 1.5-8s intervals — overlapping counts but faster rate."""
    sid = str(uuid.uuid4())
    host = str(rng.choice(HMI_RTU_HOSTS))
    user = str(rng.choice(USERS))
    ts = base_ts
    rows = []

    rows.append(_row(ts, 4624, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4624], 1, sid))
    ts = _jitter(rng, ts, 1, 10)

    # 12-25 accesses at 0.2-1.4s — faster than benign backup (1.5-8s)
    n_access = int(rng.integers(12, 26))
    for _ in range(n_access):
        obj = str(rng.choice(SCADA_OBJECTS))
        rows.append(_row(ts, 4663, SOURCES[0], user, host, f"Accessed: {obj}", 1, sid))
        ts += timedelta(seconds=float(rng.uniform(0.2, 1.4)))  # key: faster than benign

    ts = _cover_traffic(rng, ts, user, host, sid, rows, 1)
    if rng.random() < 0.20:
        rows.append(_row(ts, 4634, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4634], 1, sid))
    return rows


ATTACK_GENERATORS = [
    generate_lateral_movement,
    generate_persistence,
    generate_privilege_escalation,
    generate_reconnaissance,
]


def generate(n_benign: int, n_malicious: int, output: str, seed: int = 42):
    rng = np.random.default_rng(seed)
    random.seed(seed)

    all_rows = []
    base_ts = datetime(2024, 1, 1, 6, 0, 0)

    for _ in range(n_benign):
        offset = timedelta(minutes=int(rng.integers(0, 60 * 24 * 30)))
        all_rows.extend(generate_benign_session(rng, base_ts + offset))

    for i in range(n_malicious):
        offset = timedelta(minutes=int(rng.integers(0, 60 * 24 * 30)))
        gen = ATTACK_GENERATORS[i % len(ATTACK_GENERATORS)]
        all_rows.extend(gen(rng, base_ts + offset))

    all_rows.sort(key=lambda r: r["timestamp"])

    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "timestamp",
        "event_id",
        "source",
        "user",
        "hostname",
        "description",
        "label",
        "session_id",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    n_ev = len(all_rows)
    print(f"Generated {n_ev} events ({n_benign} benign + {n_malicious} malicious sessions)")
    print(f"Output -> {output}")


@click.command()
@click.option("--n-benign", default=5000, type=int)
@click.option("--n-malicious", default=1000, type=int)
@click.option("--output", required=True)
@click.option("--seed", default=42, type=int)
def main(n_benign, n_malicious, output, seed):
    generate(n_benign, n_malicious, output, seed)


if __name__ == "__main__":
    main()
