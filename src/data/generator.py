"""
Synthetic Windows Event Log generator for smart grid ICS/SCADA environments.
Produces labeled CSV with benign sessions and 4 malicious attack patterns.
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

UNUSUAL_PROCESSES = ["mimikatz.exe", "psexec.exe", "powershell.exe", "cmd.exe", "wce.exe"]


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


def generate_benign_session(rng, base_ts):
    sid = str(uuid.uuid4())
    host = rng.choice(SMART_GRID_HOSTS)
    user = rng.choice(USERS[:4])
    ts = base_ts
    rows = []

    # Normal logon sequence
    rows.append(_row(ts, 4624, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4624], 0, sid))
    ts = _jitter(rng, ts, 10, 300)

    # Random mix of normal activity (3-12 events)
    n_events = int(rng.integers(3, 13))
    normal_ids = [4688, 4689, 4634, 4663, 4656, 4648]
    for _ in range(n_events):
        eid = int(rng.choice(normal_ids))
        rows.append(_row(ts, eid, SOURCES[0], user, host, EVENT_DESCRIPTIONS[eid], 0, sid))
        ts = _jitter(rng, ts, 5, 180)

    # Logoff
    rows.append(_row(ts, 4634, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4634], 0, sid))
    return rows


def generate_lateral_movement(rng, base_ts):
    sid = str(uuid.uuid4())
    attacker_host = f"192.168.{rng.integers(1, 254)}.{rng.integers(1, 254)}"
    target_host = rng.choice(SCADA_HOSTS)
    user = rng.choice(USERS)
    ts = base_ts
    rows = []

    # 3-8 logon failures from unexpected source
    n_fails = int(rng.integers(3, 9))
    for _ in range(n_fails):
        desc = f"An account failed to log on. Source: {attacker_host}"
        rows.append(_row(ts, 4625, SOURCES[0], user, target_host, desc, 1, sid))
        ts = _jitter(rng, ts, 2, 15)

    # Success logon from unexpected source
    desc = f"An account was successfully logged on. Source: {attacker_host}"
    rows.append(_row(ts, 4624, SOURCES[0], user, target_host, desc, 1, sid))
    ts = _jitter(rng, ts, 5, 30)

    # Follow-up activity
    rows.append(_row(ts, 4672, SOURCES[0], user, target_host, EVENT_DESCRIPTIONS[4672], 1, sid))
    return rows


def generate_persistence(rng, base_ts):
    sid = str(uuid.uuid4())
    host = rng.choice(SCADA_HOSTS)
    user = rng.choice(USERS)
    svc_name = rng.choice(["WinUpdate32", "SvcHost64", "NetMgr", "RemoteAdminSvc"])
    ts = base_ts
    rows = []

    desc = f"A new service was installed: {svc_name}. Path: C:\\Windows\\System32\\{svc_name}.exe"
    rows.append(_row(ts, 7045, SOURCES[1], user, host, desc, 1, sid))
    ts = _jitter(rng, ts, 1, 5)

    desc = f"The {svc_name} service entered the running state."
    rows.append(_row(ts, 7036, SOURCES[1], user, host, desc, 1, sid))
    ts = _jitter(rng, ts, 2, 10)

    rows.append(_row(ts, 4688, SOURCES[0], user, host, f"Process created: {svc_name}.exe", 1, sid))
    return rows


def generate_privilege_escalation(rng, base_ts):
    sid = str(uuid.uuid4())
    host = rng.choice(SMART_GRID_HOSTS)
    user = rng.choice(USERS)
    proc = rng.choice(UNUSUAL_PROCESSES)
    ts = base_ts
    rows = []

    rows.append(_row(ts, 4672, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4672], 1, sid))
    ts = _jitter(rng, ts, 1, 8)

    desc = f"A new process has been created: {proc}. Parent: explorer.exe"
    rows.append(_row(ts, 4688, SOURCES[0], user, host, desc, 1, sid))
    ts = _jitter(rng, ts, 1, 5)

    rows.append(_row(ts, 4689, SOURCES[0], user, host, f"Process exited: {proc}", 1, sid))
    return rows


def generate_reconnaissance(rng, base_ts):
    sid = str(uuid.uuid4())
    host = rng.choice(HMI_RTU_HOSTS)
    user = rng.choice(USERS)
    ts = base_ts
    rows = []

    # Burst of 8-20 object access events within <30s
    n_access = int(rng.integers(8, 21))
    objects = [
        "\\Device\\HarddiskVolume2\\SCADA\\config.ini",
        "\\Device\\HarddiskVolume2\\RTU\\setpoints.db",
        "\\Device\\HarddiskVolume2\\historian\\archive.mdb",
    ]
    for _ in range(n_access):
        obj = rng.choice(objects)
        desc = f"An attempt was made to access an object: {obj}"
        rows.append(_row(ts, 4663, SOURCES[0], user, host, desc, 1, sid))
        ts += timedelta(seconds=float(rng.uniform(0.5, 3.0)))

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

    for i in range(n_benign):
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
