# Source Code Reference — AI Malware Detection for Smart Grid ICS

Exhaustive explanation of every module in `src/`. The synthetic data generator receives
the most detail because it is the foundation every other component depends on.

---

## Directory Map

```
src/
├── __init__.py              # marks src as a Python package
├── __main__.py              # enables `python -m src` invocation
├── cli.py                   # Click CLI — wires subcommands to module functions
│
├── data/
│   ├── __init__.py
│   ├── generator.py         # synthetic Windows Event Log generator (the core)
│   └── preprocessor.py      # stratified train/val/test split by session
│
├── features/
│   ├── __init__.py
│   └── engineer.py          # session-level feature extraction (24 features)
│
└── models/
    ├── __init__.py
    ├── train.py             # Random Forest + RandomizedSearchCV
    ├── evaluate.py          # metrics + confusion matrix PNG
    ├── ablation.py          # remove one feature group at a time
    ├── baselines.py         # 6-model comparison table
    └── multiseed_eval.py    # full pipeline repeated over N seeds
```

---

## Package Bootstrap Files

### `src/__init__.py` and subpackage `__init__.py`s

Empty files. Their sole purpose is to tell Python that `src`, `src/data`,
`src/features`, and `src/models` are packages so relative imports like
`from src.data.generator import generate` resolve correctly.

### `src/__main__.py`

```python
from src.cli import main
main()
```

Two lines. Imports the Click group entry point and calls it. This is what makes
`python -m src` work: Python looks for `__main__.py` in the package and executes it.
Without this, you must call `python -m src.cli` instead.

---

## `src/cli.py` — Command-Line Interface

**Responsibility:** single entry point that maps CLI subcommand names to the
underlying module functions. Users never import module functions directly;
they invoke this file.

### How Click groups work

```python
@click.group()
def cli():
    """AI malware detection for smart grid Windows Event Logs."""
```

`@click.group()` creates a multi-command dispatcher. Calling `python -m src`
prints available subcommands. Each subcommand is added with `@cli.command()` or
`cli.add_command(fn, name="alias")`.

### Subcommand wiring

| CLI name | Function called | Module |
|---|---|---|
| `generate` | `generate()` | `src.data.generator` |
| `preprocess` | `preprocess()` | `src.data.preprocessor` |
| `featurize` | `engineer()` | `src.features.engineer` |
| `train` | `train()` | `src.models.train` |
| `evaluate` | `evaluate()` | `src.models.evaluate` |
| `baselines` | `run_baselines()` | `src.models.baselines` |
| `multiseed` | `run_multiseed()` | `src.models.multiseed_eval` |

### Why the duplicate `add_command` calls?

```python
@cli.command()
...
def generate_cmd(...):
    ...

cli.add_command(generate_cmd, name="generate")
```

`@cli.command()` registers the function under its Python name (`generate_cmd`).
`cli.add_command(..., name="generate")` re-registers the same function under the
canonical name. This lets the function have a Python-safe name (avoiding collision
with the imported `generate` function from generator.py) while the CLI name stays
clean.

### `main()` at the bottom

```python
def main():
    cli()
```

This wrapper is what `pyproject.toml` would point to for a `[project.scripts]` entry
point. It is also called by `__main__.py`.

---

## `src/data/generator.py` — Synthetic Windows Event Log Generator

This is the most complex module. It produces the entire dataset from scratch.

### Design Philosophy: Non-Trivially Separable Data

The module-level docstring explains the core design constraint:

```
Design v3 — Non-trivially separable data:
Benign sessions are intentionally noisy with events that also appear in attack
patterns at rates high enough that NO SINGLE feature group achieves perfect
classification alone.
```

**Why this matters.** A naive generator would make attack sessions contain only
attack-specific event IDs and benign sessions contain only benign-specific ones.
This creates a trivially separable dataset where checking a single count feature
gives F1 = 1.00. Such results are scientifically worthless: they test whether the
model can memorise the generator logic, not whether the features contain real
discriminative signal.

**Calibration targets** (documented in the docstring):

| Feature | Benign sessions | Malicious sessions |
|---|---|---|
| `count_4625` (logon failures) | 0–2 failures (85%), 3–15 (15%) | 6–14 failures (lateral movement) |
| `count_7045` (service install) | present in 30% of sessions | always present in persistence attacks |
| `count_4663` (object access) | burst in 30% of sessions (4–15 events, 1.5–8s intervals) | burst in recon (12–25 events, 0.2–1.4s) |
| `count_4672` (special privs) | present in 50% of sessions | always present in privesc attacks |

The deliberate overlap forces the model to use **combinations** of features, not
single features. The ablation study validates this: Group 1 alone drops F1 by 0.056,
not by 0.999.

---

### Global Constants

#### `SMART_GRID_HOSTS`

```python
SMART_GRID_HOSTS = [
    "SCADA-HMI-01", "SCADA-HMI-02",
    "RTU-CTRL-03",  "RTU-CTRL-04",
    "eng_station", "historian", "dmz-fw-01",
]
```

Seven hostnames following real utility naming conventions:
- `SCADA-HMI-*`: Supervisory Control and Data Acquisition human-machine interface workstations
- `RTU-CTRL-*`: Remote Terminal Unit controllers (Purdue Level 1 devices)
- `eng_station`: engineering workstation used for configuration changes
- `historian`: data historian server — archives process measurements
- `dmz-fw-01`: firewall in the IT/OT demilitarised zone

Two sub-lists are derived:
```python
SCADA_HOSTS     = ["SCADA-HMI-01", "SCADA-HMI-02", "RTU-CTRL-03", "RTU-CTRL-04"]
HMI_RTU_HOSTS   = ["SCADA-HMI-01", "SCADA-HMI-02", "RTU-CTRL-03", "RTU-CTRL-04"]
```

Attack generators target `SCADA_HOSTS` / `HMI_RTU_HOSTS` specifically. Attackers
prioritise SCADA and RTU hosts because they have direct control-plane access.
Benign sessions use the full `SMART_GRID_HOSTS` list.

#### `USERS`

```python
USERS = ["operator1", "operator2", "eng_admin", "svc_historian", "svc_scada", "SYSTEM"]
```

Six accounts representing realistic ICS roles:
- `operator1`, `operator2`: human SCADA operators (normal daytime users)
- `eng_admin`: engineering admin with elevated privileges
- `svc_historian`: service account for the historian process
- `svc_scada`: service account for the SCADA server daemon
- `SYSTEM`: Windows built-in system account (appears in service and kernel events)

Benign sessions pick from `USERS[:4]` (first four). Attack sessions pick from the
full list — attackers may impersonate service accounts or escalate to SYSTEM.

#### `SOURCES`

```python
SOURCES = [
    "Microsoft-Windows-Security-Auditing",
    "Service Control Manager",
    "Microsoft-Windows-Kernel-Process",
]
```

Real Windows Event Log provider names:
- `Microsoft-Windows-Security-Auditing`: generates logon (4624, 4625, 4634, 4648,
  4672), object access (4663, 4656), and account management (4720, 4732) events
- `Service Control Manager`: generates service events (7045, 7036)
- `Microsoft-Windows-Kernel-Process`: generates process events (4688, 4689)

In the generated rows, `source` is assigned per event ID to match real provider
behaviour. Security-related events use `SOURCES[0]`, service events use `SOURCES[1]`.

#### `LEGIT_PROCESSES` and `OFFENSIVE_PROCESSES`

```python
LEGIT_PROCESSES = [
    "explorer.exe", "taskmgr.exe", "mmc.exe", "powershell.exe",
    "cmd.exe", "python.exe", "java.exe", "svchost.exe", "wscript.exe",
]

OFFENSIVE_PROCESSES = ["mimikatz.exe", "psexec.exe", "wce.exe", "meterpreter.exe", "nc.exe"]
```

Legitimate processes include `powershell.exe` and `cmd.exe` intentionally. These
appear in both benign admin work and attack sessions. This means `count_4688` alone
cannot distinguish benign from malicious — the model must also look at the `description`
field content and the surrounding event pattern. `OFFENSIVE_PROCESSES` are always
malicious-context: `mimikatz.exe` is a credential-theft tool, `psexec.exe` is remote
execution, `wce.exe` is Windows Credential Editor, `meterpreter.exe` is a Metasploit
payload, `nc.exe` is netcat.

#### `LEGIT_SERVICES` and `OFFENSIVE_SERVICES`

```python
LEGIT_SERVICES = [
    "WUAutoupdate", "BackupAgent", "AVScanner",
    "PolicyUpdater", "WSUS_Client", "SolarwindsAgent", "VeeamAgent",
]

OFFENSIVE_SERVICES = [
    "WinUpdate32", "SvcHost64", "NetMgr",
    "RemoteAdminSvc", "TelnetSvc", "RemDesktopSvc",
]
```

Benign service installs use `LEGIT_SERVICES` (Windows Update, antivirus, backup
agents). Offensive services use `OFFENSIVE_SERVICES` — names deliberately designed
to look plausible but not match any real Microsoft or standard software service.
This distinction contributes to feature discrimination via the `description` field
content, though the structured features (counts, timing) carry more signal.

#### `SCADA_OBJECTS`

```python
SCADA_OBJECTS = [
    "\\Device\\HarddiskVolume2\\SCADA\\config.ini",
    "\\Device\\HarddiskVolume2\\RTU\\setpoints.db",
    "\\Device\\HarddiskVolume2\\historian\\archive.mdb",
    "\\Device\\HarddiskVolume2\\Reports\\daily.xlsx",
    "\\Device\\HarddiskVolume2\\Backup\\logs.tar",
    "\\Device\\HarddiskVolume2\\OPC\\tags.xml",
]
```

Windows device path format for file system objects. These are the targets of
Event 4663 (object access). All paths point to ICS-relevant files: SCADA config,
RTU setpoint database, historian archive, OPC tag definitions. Using ICS-specific
paths makes the simulation contextually accurate.

#### `EVENT_DESCRIPTIONS`

```python
EVENT_DESCRIPTIONS = {
    4624: "An account was successfully logged on.",
    4625: "An account failed to log on.",
    ...
}
```

Verbatim text from real Windows Event Log entries. Used as the `description` column
value. Some generators append extra context (e.g., `f"Failed logon from {attacker_ip}"`)
to make individual rows richer, but the structured feature engineering ignores the
description field — only event_id, timestamp, source, user, hostname matter for features.

---

### Helper Functions

#### `_row(ts, event_id, source, user, hostname, description, label, session_id)`

```python
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
```

Pure factory function. Takes a `datetime` object and all field values, returns a
dict with `timestamp` converted to ISO-8601 string (`2024-01-15T08:23:41`).

Every generator calls this for every event. The consistent field names match the
CSV column headers written by `generate()`. `label` is always 0 for benign, 1 for
malicious — set at the row level, then aggregated to session level during feature
engineering (session label = max of row labels).

#### `_jitter(rng, base_ts, min_s=5, max_s=120)`

```python
def _jitter(rng, base_ts, min_s=5, max_s=120):
    return base_ts + timedelta(seconds=int(rng.integers(min_s, max_s)))
```

Adds a random integer number of seconds to a timestamp, drawn uniformly from
`[min_s, max_s)`. Used everywhere to advance time between events.

`rng` is a `numpy.random.Generator` (from `np.random.default_rng(seed)`). Using
numpy's Generator instead of Python's `random` module ensures reproducibility is
controlled by the numpy seed while keeping the distribution uniform over integers.

`int(rng.integers(...))` converts the numpy int64 to a plain Python int before
passing to `timedelta`, avoiding numpy type propagation.

#### `_cover_traffic(rng, ts, user, host, sid, rows, label)`

```python
def _cover_traffic(rng, ts, user, host, sid, rows, label):
    """Insert 1-3 normal-looking events with long gaps to break td separation."""
    n = int(rng.integers(1, 4))
    normal_ids = [4688, 4689, 4656, 4648]
    for _ in range(n):
        eid = int(rng.choice(normal_ids))
        ts = _jitter(rng, ts, 30, 180)   # ← long pause
        rows.append(_row(ts, eid, SOURCES[0], user, host, EVENT_DESCRIPTIONS[eid], label, sid))
    return ts
```

**This function is the key anti-circular-evaluation mechanism.**

Without cover traffic, attack sessions have short inter-event gaps throughout
(e.g., recon bursts events every 0.2–1.4s). Computing `td_max` or `td_mean`
would trivially separate benign from malicious with F1 = 1.00 on a single feature.

Cover traffic inserts 1–3 extra events (drawn from normal-looking event IDs: process
creation/exit, object handle, explicit credentials) with gaps of **30–180 seconds**.
These long-gap events push `td_max` and `td_mean` into the benign range for some
attack sessions.

The function is called at the **end** of each attack generator after the signature
events are placed. This means the attack signature events still exist and carry
discriminative signal, but the session's overall timing statistics are diluted
enough that no single timing feature achieves perfect separation.

`rows` is mutated in-place (Python list). The function also returns the new
timestamp so the caller can optionally append a logoff event after.

---

### Benign Session Generator

```python
def generate_benign_session(rng, base_ts):
```

Produces one benign session (label=0). Called `n_benign` times in `generate()`.

#### Step 1 — Session identity

```python
sid = str(uuid.uuid4())
host = str(rng.choice(SMART_GRID_HOSTS))
user = str(rng.choice(USERS[:4]))
ts = base_ts
rows = []
```

A UUID4 session ID uniquely identifies this session. `USERS[:4]` excludes service
accounts and SYSTEM — benign sessions are human operators or the engineering admin.
`ts` starts at `base_ts` (a random offset from Jan 1 2024 06:00:00) and advances
with each event.

#### Step 2 — Initial logon (Event 4624)

```python
src_ip = ""
if rng.random() < 0.15:   # 15% remote logon
    a = int(rng.integers(0, 255))
    b = int(rng.integers(0, 255))
    c = int(rng.integers(1, 254))
    src_ip = f" Source: 10.{a}.{b}.{c}"
rows.append(_row(ts, 4624, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4624] + src_ip, 0, sid))
ts = _jitter(rng, ts, 5, 120)
```

Every session starts with a logon. 15% of benign sessions add an internal IP address
to the description, simulating remote desktop or VPN sessions from a management
workstation. This is realistic (operators sometimes log in remotely) and makes the
benign sessions slightly more diverse. The `src_ip` is a 10.x.x.x address (RFC 1918
private range), appropriate for an internal network.

The post-logon gap is 5–120 seconds: operator thinks, opens application.

#### Step 3 — Logon failures (Event 4625)

```python
if rng.random() < 0.85:
    n_fails = int(rng.integers(0, 3))     # 0, 1, or 2 failures
else:
    n_fails = int(rng.integers(3, 16))    # 3 to 15 failures
```

**This is the most critical calibration decision for anti-circular-evaluation.**

85% of benign sessions produce 0–2 logon failures (normal typo rate). 15% produce
3–15 failures — simulating lockout scenarios, forgotten passwords, or automated
scripts retrying with wrong credentials.

This overlaps directly with the lateral movement attack (6–14 failures). If benign
always had 0–2 and attacks always had 6+, `count_4625 > 3` would be a perfect
classifier. The 15% tail of benign failures prevents this.

Failure events have a gap of 1–12 seconds between them (fast retries, like typing
wrong password multiple times). This is the same range as attack failures, making
count and timing of failures alone insufficient for discrimination.

#### Step 4 — Privilege escalation noise (Event 4672 + 4688)

```python
if rng.random() < 0.50:
    rows.append(_row(ts, 4672, ...))
    ts = _jitter(rng, ts, 1, 30)    # variable gap
    proc = str(rng.choice(LEGIT_PROCESSES))
    rows.append(_row(ts, 4688, ..., f"Process created: {proc}", ...))
    ts = _jitter(rng, ts, 5, 60)
    rows.append(_row(ts, 4689, ..., f"Process exited: {proc}", ...))
```

50% of benign sessions include a special-privileges event (4672) followed by a
process creation with a legitimate process. The gap between 4672 and 4688 is 1–30
seconds — overlapping with the attack pattern (1–4 seconds). This prevents using
`td_min` between 4672→4688 as a standalone classifier.

The key remaining difference: benign uses `LEGIT_PROCESSES`, attacks use
`OFFENSIVE_PROCESSES`. But process name is in the `description` text field,
not a structured feature column — the structured features see only counts and timing.

#### Step 5 — Service installation noise (Events 7045 + 7036)

```python
if rng.random() < 0.30:
    svc = str(rng.choice(LEGIT_SERVICES))
    rows.append(_row(ts, 7045, SOURCES[1], user, host, f"Service installed: {svc}", 0, sid))
    ts = _jitter(rng, ts, 5, 60)     # benign: 5-60s gap
    rows.append(_row(ts, 7036, SOURCES[1], user, host, f"{svc} state change", 0, sid))
    ts = _jitter(rng, ts, 10, 120)
```

30% of benign sessions include service installation (Windows Update, AV scanner,
backup agent). The attack persistence pattern also installs a service, but with:
- Gap of 1–4 seconds (not 5–60)
- Offensive service name
- Immediately followed by 4688 process creation

The gap difference is the primary discriminator here. Benign service installs have
longer delays before state change because the service control manager starts the
service asynchronously.

**Why 30%?** This was tuned specifically so `count_7045` alone cannot classify:
30% benign sessions have 7045 (false positive baseline), and all persistence attacks
have 7045 (true positive). A threshold on `count_7045 >= 1` would have ~30% false
positive rate — poor precision.

#### Step 6 — Object access burst noise (Event 4663)

```python
if rng.random() < 0.30:
    n_access = int(rng.integers(4, 16))   # 4-15 accesses
    for _ in range(n_access):
        obj = str(rng.choice(SCADA_OBJECTS))
        rows.append(_row(ts, 4663, ..., f"Scheduled access: {obj}", 0, sid))
        ts += timedelta(seconds=float(rng.uniform(1.5, 8.0)))  # 1.5-8s intervals
```

30% of benign sessions generate a burst of 4–15 object access events at 1.5–8.0
second intervals. This simulates backup jobs, scheduled report generation, or AV
scans that rapidly traverse SCADA configuration files.

Reconnaissance attacks generate 12–25 accesses at **0.2–1.4 second** intervals.
The count ranges overlap (4–15 vs 12–25, overlapping at 12–15). The timing ranges
do not overlap (benign minimum 1.5s, attack maximum 1.4s). But cover traffic dilutes
the timing signal, so this is not a perfect separator.

#### Step 7 — Core normal activity

```python
n_events = int(rng.integers(3, 11))
normal_ids = [4688, 4689, 4663, 4656, 4648]
for _ in range(n_events):
    eid = int(rng.choice(normal_ids))
    rows.append(_row(ts, eid, SOURCES[0], user, host, EVENT_DESCRIPTIONS[eid], 0, sid))
    ts = _jitter(rng, ts, 10, 300)
```

3–10 additional events drawn from common operational IDs with 10–300 second gaps
(normal operator think-time). These increase `count_total` and create the long
inter-event gaps characteristic of benign sessions.

#### Step 8 — Logoff (Event 4634)

```python
if rng.random() < 0.80:
    rows.append(_row(ts, 4634, SOURCES[0], user, host, EVENT_DESCRIPTIONS[4634], 0, sid))
```

80% probability, not 100%. Simulates connection drops, session timeouts without
explicit logoff, and workstations left logged in. This prevents `count_4634 == 0`
from being a strong malicious indicator (attack sessions have only 20% logoff rate,
benign sessions have 20% no-logoff rate — ranges overlap).

---

### Attack Session Generators

All attack generators share a common structure:
1. Generate session UUID + pick target host and user
2. Emit the attack-signature events (the "signal")
3. Call `_cover_traffic()` to dilute timing signal
4. Optional logoff at 20% probability

#### `generate_lateral_movement(rng, base_ts)`

**MITRE ATT&CK for ICS:** T0812 (Default Credentials) / T0886 (Remote Services)

**Key signal:** high count of 4625 failures from a single external IP, followed by
4624 success from the same IP, followed immediately by privilege use and offensive
process.

```python
attacker_ip = f"192.168.{int(rng.integers(1,254))}.{int(rng.integers(1,254))}"
target_host = str(rng.choice(SCADA_HOSTS))
```

Uses 192.168.x.x (private range) as attacker IP — this is an internal network
attacker who has compromised a machine inside the corporate network.

```python
n_fails = int(rng.integers(6, 15))   # 6 to 14 failures
for _ in range(n_fails):
    rows.append(_row(ts, 4625, ..., f"Failed logon from {attacker_ip}", 1, sid))
    ts = _jitter(rng, ts, 1, 6)      # 1-6s between failures (fast retry)
```

6–14 failures at 1–6 second intervals. Faster and more numerous than benign failures.
Same source IP for all failures — in a real log, this is the primary indicator;
in structured features it contributes to `count_4625` and `n_unique_sources`
(cardinality feature Group 3).

```python
rows.append(_row(ts, 4624, ..., f"Logon success from {attacker_ip}", 1, sid))
ts = _jitter(rng, ts, 1, 8)

rows.append(_row(ts, 4672, ..., EVENT_DESCRIPTIONS[4672], 1, sid))
ts += timedelta(seconds=int(rng.integers(1, 4)))   # 1-3s gap to process
proc = str(rng.choice(OFFENSIVE_PROCESSES))
rows.append(_row(ts, 4688, ..., f"Process created: {proc}", 1, sid))
```

Privilege assignment immediately followed (1–3 seconds) by an offensive process.
This very short 4672→4688 gap is a timing signal that overlaps with benign (benign
has 1–30s), but combined with the preceding failure burst, produces a distinctive
multi-feature pattern.

```python
ts = _cover_traffic(rng, ts, user, target_host, sid, rows, 1)
```

Cover traffic appended after the signature events. Adds 1–3 normal events with
30–180 second gaps, diluting `td_max` and `td_mean`.

---

#### `generate_persistence(rng, base_ts)`

**MITRE ATT&CK for ICS:** T0839 (Module Firmware) / T0859 (Valid Accounts — persistence)

**Key signal:** offensive service install with sub-5-second inter-event gaps,
immediately followed by process creation using an offensive binary.

```python
svc = str(rng.choice(OFFENSIVE_SERVICES))
...
rows.append(_row(ts, 4672, ...))
ts += timedelta(seconds=int(rng.integers(1, 5)))   # short: 1-4s (benign: 5-60s)
rows.append(_row(ts, 7045, ..., f"Service installed: {svc}", 1, sid))
ts += timedelta(seconds=int(rng.integers(1, 4)))   # very short: 1-3s (benign: 5-60s)
rows.append(_row(ts, 7036, ..., f"{svc} entered running state", 1, sid))
ts += timedelta(seconds=int(rng.integers(1, 4)))
proc = str(rng.choice(OFFENSIVE_PROCESSES))
rows.append(_row(ts, 4688, ..., f"Process created: {proc} parent={svc}", 1, sid))
```

Four events in rapid succession: 4672 → 7045 → 7036 → 4688. Gaps between them are
all 1–4 seconds. Benign service installs have 5–60 second gaps. This gap difference
is the primary discriminator for this attack type.

The `description` field records the parent-service relationship (`parent={svc}`),
but this field is not used by the structured feature extractor.

---

#### `generate_privilege_escalation(rng, base_ts)`

**MITRE ATT&CK for ICS:** T0890 (Exploitation for Privilege Escalation)

**Key signal:** 4672 immediately followed by an offensive process (1–3 second gap).

```python
rows.append(_row(ts, 4672, ...))
ts += timedelta(seconds=int(rng.integers(1, 4)))   # 1-3s — overlaps benign (1-30s)
proc = str(rng.choice(OFFENSIVE_PROCESSES))
rows.append(_row(ts, 4688, ..., f"Process created: {proc} (elevated)", 1, sid))
ts = _jitter(rng, ts, 1, 5)
rows.append(_row(ts, 4689, ..., f"Process exited: {proc}", 1, sid))
```

The 1–3 second gap overlaps with benign (1–30 seconds), which is intentional. The
primary discriminator here is the process name (offensive binary). Since the
feature extractor does not read the description field, the model must rely on:
- `count_4672` + `count_4688` combination (both present)
- `td_min` being small (1–3s gap between 4672 and 4688)
- Absence of normal process count pattern seen in benign sessions

This attack type has the subtlest structured-feature signature of the four, which
is why it contributes to the ablation showing non-trivial but incomplete separation.

---

#### `generate_reconnaissance(rng, base_ts)`

**MITRE ATT&CK for ICS:** T0840 (Network Connection Enumeration) / T0888 (Remote System
Information Discovery)

**Key signal:** dense, rapid burst of object access events at sub-1.5-second intervals
on HMI/RTU hosts.

```python
host = str(rng.choice(HMI_RTU_HOSTS))   # restricted to HMI/RTU targets
...
n_access = int(rng.integers(12, 26))    # 12-25 accesses
for _ in range(n_access):
    obj = str(rng.choice(SCADA_OBJECTS))
    rows.append(_row(ts, 4663, ..., f"Accessed: {obj}", 1, sid))
    ts += timedelta(seconds=float(rng.uniform(0.2, 1.4)))   # 0.2-1.4s — faster than benign
```

The access rate of 0.2–1.4 seconds per event is the defining characteristic.
Benign backup/scan operations use 1.5–8.0 seconds per access. There is no overlap
in the interval ranges (benign minimum is 1.5s, attack maximum is 1.4s). However,
`td_min` alone does not achieve F1=1.00 because cover traffic adds long-gap events
that affect `td_max` and `td_mean`, making single timing features ambiguous.

---

#### `generate_evasive_lateral_movement(rng, base_ts)`

**Adversarial variant** of lateral movement. Designed to defeat timing-based detection
by mimicking benign inter-event gaps.

```python
n_fails = int(rng.integers(3, 6))          # fewer failures (3-5 vs normal 6-14)
for _ in range(n_fails):
    ...
    ts += timedelta(seconds=int(rng.integers(60, 300)))   # 60-300s between failures
```

The attacker:
1. Uses only 3–5 failures (overlaps with benign's 15% tail of 3–15 failures)
2. Spaces failures **60–300 seconds apart** (mimicking legitimate typos over time, not brute-force)
3. Waits 10–120 seconds after successful logon before acting (benign-like pause)
4. Uses a 5–60 second gap between 4672 and offensive process (same as benign range)

```python
ts = _jitter(rng, ts, 5, 60)    # benign-range gap between 4672 and process
```

This variant can evade `td_min`-based detection because the inter-failure gaps are
in the benign range. It still has an offensive process name in the description and
the pattern of external IP → privileges → offensive process, but these are
structurally weaker signals in the feature space.

Result: single-feature maximum F1 drops from ~1.00 to ~0.86 when evasive variants
are included.

---

#### `generate_evasive_reconnaissance(rng, base_ts)`

**Adversarial variant** of reconnaissance. Rate-limits the access burst to overlap
with benign backup operations.

```python
n_access = int(rng.integers(8, 15))     # 8-14 accesses (vs normal 12-25)
for _ in range(n_access):
    obj = str(rng.choice(SCADA_OBJECTS))
    rows.append(_row(ts, 4663, ...))
    ts += timedelta(seconds=float(rng.uniform(2.0, 9.0)))   # 2-9s (overlaps benign 1.5-8s)
```

Access intervals of 2.0–9.0 seconds overlap with benign's 1.5–8.0 second range
(overlap zone: 2.0–8.0 seconds). `td_min` cannot reliably distinguish these from
benign backup scans. The model must rely on the count of 4663 events (8–14 vs benign
4–15, significant overlap) combined with the absence of other normal activity events.

---

### `ATTACK_GENERATORS` List

```python
ATTACK_GENERATORS = [
    generate_lateral_movement,
    generate_persistence,
    generate_privilege_escalation,
    generate_reconnaissance,
    generate_evasive_lateral_movement,
    generate_evasive_reconnaissance,
]
```

Six generators. The `generate()` function assigns them to malicious sessions
cyclically:

```python
gen = ATTACK_GENERATORS[i % len(ATTACK_GENERATORS)]
```

With 1,000 malicious sessions and 6 generators, each generator handles
approximately 167 sessions. The distribution is:
- `generate_lateral_movement`: sessions 0, 6, 12, ...
- `generate_persistence`: sessions 1, 7, 13, ...
- `generate_privilege_escalation`: sessions 2, 8, 14, ...
- `generate_reconnaissance`: sessions 3, 9, 15, ...
- `generate_evasive_lateral_movement`: sessions 4, 10, 16, ...
- `generate_evasive_reconnaissance`: sessions 5, 11, 17, ...

This ensures all attack types are well-represented without requiring separate
count parameters per attack type.

---

### `generate()` — Top-Level Orchestrator

```python
def generate(n_benign: int, n_malicious: int, output: str, seed: int = 42):
    rng = np.random.default_rng(seed)
    random.seed(seed)
```

Two random number generators are seeded:
- `rng`: numpy Generator, used by all session generators via `rng.integers()`,
  `rng.choice()`, `rng.random()`, `rng.uniform()`
- `random.seed(seed)`: seeds Python's built-in random module. None of the current
  code uses `random.*` directly, but this guard ensures any future stdlib random
  calls are reproducible.

```python
base_ts = datetime(2024, 1, 1, 6, 0, 0)

for _ in range(n_benign):
    offset = timedelta(minutes=int(rng.integers(0, 60 * 24 * 30)))
    all_rows.extend(generate_benign_session(rng, base_ts + offset))
```

Sessions are not sequential in time. Each session gets a random offset up to 30
days from `base_ts` (2024-01-01 06:00:00). This means sessions overlap in wall-clock
time, simulating a real environment where many operators log in concurrently.

The resulting `all_rows` list is then **globally sorted by timestamp**:

```python
all_rows.sort(key=lambda r: r["timestamp"])
```

This sort is important: the CSV is written in chronological order, interleaving
events from different sessions (benign and malicious). The feature extractor later
groups by `session_id`, so the sort order in the CSV doesn't affect features, but
chronological order makes the file realistic and easier to inspect.

#### CSV writing

```python
fieldnames = ["timestamp", "event_id", "source", "user", "hostname",
              "description", "label", "session_id"]
with open(out_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_rows)
```

`csv.DictWriter` with explicit `fieldnames` ensures column order is deterministic
regardless of dict insertion order. `newline=""` is required by the csv module on
Windows to prevent double `\r\n` line endings.

---

## `src/data/preprocessor.py` — Train/Val/Test Splitter

**Responsibility:** clean the raw CSV and produce three splits with the class ratio
preserved in each.

### Session-level label derivation

```python
session_labels = df.groupby("session_id")["label"].max().reset_index()
```

Individual events have row-level labels (0 or 1). A session is malicious if **any**
event in it has label=1. `groupby().max()` implements this: max of [0,0,1,0] = 1.

This is the canonical session-level label. Benign sessions always produce max=0
because all their rows have label=0. Attack sessions always produce max=1.

### Stratified split logic

```python
train_ids, temp_ids, _, temp_labels = train_test_split(
    sessions, labels, test_size=0.30, stratify=labels, random_state=42
)
val_ids, test_ids = train_test_split(
    temp_ids, test_size=0.50, stratify=temp_labels, random_state=42
)
```

Two-stage split to achieve 70/15/15:
1. First split: 70% train, 30% temp
2. Second split: temp split 50/50 into val and test (50% of 30% = 15% each)

`stratify=labels` preserves the 5:1 benign/malicious ratio in each partition.
Without stratification, small test sets could randomly contain far fewer malicious
sessions, making metrics unreliable.

The split is on **session IDs**, not on individual event rows. This is critical: if
you split on rows, events from the same session could appear in both train and test,
causing data leakage. Splitting on session IDs guarantees no session appears in
multiple partitions.

### Output

Three CSV files in the output directory: `train.csv`, `val.csv`, `test.csv`. Each
contains all event rows for the sessions assigned to that split. The `session_id`
column is preserved, allowing the feature extractor to re-group events correctly.

---

## `src/features/engineer.py` — Feature Extraction

**Responsibility:** transform raw event rows into one feature vector per session.

### Constants

```python
COUNT_EVENT_IDS = [4624, 4625, 4634, 4648, 4672, 4688, 4689, 4720, 4732, 7045, 7036, 4663, 4656]
RARE_THRESHOLD = 0.05
```

`COUNT_EVENT_IDS` — all 13 event IDs used in the generator. One count feature per ID
plus a total, giving 14 count features (Group 1).

`RARE_THRESHOLD` — 5%. An event ID is "rare" if it appears in fewer than 5% of benign
training sessions. Rare events become binary flag features (Group 4).

### `_shannon_entropy(series)`

```python
def _shannon_entropy(series: pd.Series) -> float:
    counts = series.value_counts(normalize=True)
    return float(scipy_entropy(counts.values, base=2)) if len(counts) > 1 else 0.0
```

Computes Shannon entropy of the event ID distribution within a session.
`normalize=True` gives proportions (probability mass per event ID).
`scipy.stats.entropy` with `base=2` gives entropy in bits.

Sessions with all events of the same type (e.g., 20 consecutive 4663 events in recon)
have low entropy (≈ 0 bits). Sessions with diverse event types (benign operators doing
many different things) have high entropy.

Returns 0.0 for single-event sessions (entropy undefined for a single symbol).

### `identify_rare_events(train_df)`

```python
def identify_rare_events(train_df: pd.DataFrame) -> list[int]:
    benign = train_df[train_df["label"] == 0]
    n_benign_sessions = benign["session_id"].nunique()
    event_session_counts = benign.groupby("event_id")["session_id"].nunique() / n_benign_sessions
    rare = event_session_counts[event_session_counts < RARE_THRESHOLD].index.tolist()
    return [int(e) for e in rare]
```

Looks only at **benign training sessions**. For each event ID, counts how many
distinct benign sessions contain at least one occurrence of that event. Divides by
total benign sessions to get the prevalence fraction. Event IDs with prevalence < 5%
become rare flags.

**Why computed on training data only?** Rare flags must be determined from the
training set and then applied identically to val and test. Computing on val/test
would constitute data leakage. The `rare_event_ids` list from training is passed
as a parameter to `extract_features()` for val and test.

**Current behaviour with this dataset:** Because 30% of benign sessions contain
7045 and 50% contain 4672, neither event is "rare" in benign sessions. The rare
flag list will typically be empty or contain only infrequent event IDs. This means
Group 4 features add no columns in practice, which the ablation study confirms
(ΔF1 = 0.000 for Group 4).

### `extract_features(df, rare_event_ids)`

The main feature extraction loop. Iterates over every unique `session_id`:

```python
for sid, group in df.groupby("session_id"):
    group = group.sort_values("timestamp")
    feat: dict = {"session_id": sid}
```

#### Group 1 — Event frequency counts (14 features)

```python
for eid in COUNT_EVENT_IDS:
    feat[f"count_{eid}"] = int((group["event_id"] == eid).sum())
feat["count_total"] = len(group)
```

Simple count of occurrences per event ID, plus total event count. Named
`count_4624`, `count_4625`, ..., `count_4656`, `count_total`.

#### Group 2 — Time-delta statistics (4 features)

```python
ts_sorted = group["timestamp"].values
if len(ts_sorted) > 1:
    deltas = np.diff(ts_sorted.astype("datetime64[s]").astype(np.int64))
    feat["td_mean"] = float(deltas.mean())
    feat["td_std"]  = float(deltas.std())
    feat["td_min"]  = float(deltas.min())
    feat["td_max"]  = float(deltas.max())
else:
    feat["td_mean"] = feat["td_std"] = feat["td_min"] = feat["td_max"] = 0.0
```

Converts timestamp array to `datetime64[s]` (second precision), then to int64
(seconds since epoch). `np.diff` computes consecutive differences. All delta values
are in **seconds**.

The conversion chain `datetime64[s] → int64` is important: direct subtraction of
`datetime64` values gives `timedelta64`, which requires an extra conversion step.
The int64 path is simpler and avoids pandas/numpy type ambiguity.

Single-event sessions get 0.0 for all time-delta features (no gap to compute).

#### Group 3 — Cardinality (3 features)

```python
feat["n_unique_sources"] = int(group["source"].nunique())
feat["n_unique_users"]   = int(group["user"].nunique())
feat["n_unique_hosts"]   = int(group["hostname"].nunique())
```

Counts unique values in the source, user, and hostname columns within the session.
Lateral movement attacks generate events from the attacker's IP in the description,
but the `source` column (event provider name) stays constant — so `n_unique_sources`
primarily distinguishes sessions where different Windows subsystems (Security
Auditing vs Service Control Manager) generate events.

#### Group 4 — Rare event flags

```python
feat.update(_compute_rare_flags(group, rare_event_ids))
```

`_compute_rare_flags` returns `{"flag_NNNN": 1}` for each rare event ID present in
the session, `{"flag_NNNN": 0}` otherwise. With an empty `rare_event_ids` list,
this adds no columns.

#### Group 5 — Sequence entropy (1 feature)

```python
feat["seq_entropy"] = _shannon_entropy(group["event_id"])
```

Shannon entropy over the event ID distribution in this session.

#### Session label

```python
feat["label"] = int(group["label"].max())
```

Aggregates row-level labels to session level (max = any malicious event makes the
session malicious). Consistent with the preprocessor's label derivation.

### `engineer()` function flow

```python
train_df = pd.read_csv(in_path / "train.csv")
rare_ids = identify_rare_events(train_df)   # computed once from training data

for split in ["train", "val", "test"]:
    raw = pd.read_csv(in_path / f"{split}.csv")
    features = extract_features(raw, rare_ids)  # same rare_ids for all splits
    features.to_csv(out_path / f"{split}_features.csv", index=False)
```

The rare event IDs list is computed once from training data and reused for all
three splits. This is the correct approach to prevent leakage.

---

## `src/models/train.py` — Model Training

**Responsibility:** find the best Random Forest hyperparameters via cross-validation
and save the final model.

### Why Random Forest?

The module-level comment explains:
- Handles heterogeneous tabular features (counts, statistics, binary flags) without
  feature scaling — tree splits work on any monotone transform of a feature
- `class_weight='balanced'` compensates for 5:1 class imbalance by assigning
  weights inversely proportional to class frequency, without oversampling
- Feature importances provide academic interpretability (used in the paper)
- Robust hyperparameters — no convergence issues unlike SVM or neural networks
  on datasets of this size

### `_load_features(path)`

```python
def _load_features(path: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    df = pd.read_csv(path)
    feat_cols = [c for c in df.columns if c not in FEATURE_COLS_EXCLUDE]
    X = df[feat_cols].values.astype(np.float32)
    y = df["label"].values.astype(int)
    return X, y, feat_cols
```

`FEATURE_COLS_EXCLUDE = {"session_id", "label"}`. Everything else is a feature.
Returns `feat_cols` (list of column names) so the saved model artifact can reconstruct
the feature matrix from any future CSV in the correct column order.

Casting to `float32` reduces memory and is compatible with scikit-learn's
`RandomForestClassifier`.

### Hyperparameter search space

```python
param_dist = {
    "n_estimators":    [50, 100, 200],
    "max_depth":       [5, 10, None],
    "min_samples_split": [2, 5, 10],
    "max_features":    ["sqrt", "log2"],
}
```

`RandomizedSearchCV` with `n_iter=20` tries 20 random combinations out of the
3×3×3×2 = 54 possible configurations. This is faster than exhaustive grid search
while covering the important hyperparameter space.

`max_depth=None` means trees grow until all leaves are pure — often the best setting
for Random Forests since individual tree overfitting is corrected by ensembling.

`max_features="sqrt"` means each split considers √(n_features) ≈ 5 features,
the standard for classification. `"log2"` considers log₂(n_features) ≈ 5 features
(similar for 24 features).

### Cross-validation setup

```python
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
search = RandomizedSearchCV(..., cv=cv, scoring="f1_macro", ...)
search.fit(X_train, y_train)
```

`StratifiedKFold` with `shuffle=True` preserves the class ratio in each fold and
randomises which samples go to which fold. `f1_macro` is the optimisation target:
it computes F1 for each class separately then averages, giving equal weight to
benign and malicious classes regardless of class imbalance.

The search runs on `X_train` only (not val). Val is held out for the final fit.

### Final model fit

```python
X_trainval = np.vstack([X_train, X_val])
y_trainval = np.concatenate([y_train, y_val])

final_clf = RandomForestClassifier(**search.best_params_, class_weight="balanced", ...)
final_clf.fit(X_trainval, y_trainval)
```

After finding the best hyperparameters on train+CV, the final model is trained on
the combined train+val set. This maximises the amount of data the final model sees
while keeping the test set completely untouched.

### Model persistence

```python
joblib.dump({"model": final_clf, "feature_cols": feat_cols}, model_path)
```

Saves a dict containing both the model and the feature column names. Downstream
modules (evaluate, ablation, baselines, multiseed) load this artifact and use
`feat_cols` to select the right columns from any feature CSV, ensuring column
alignment even if the CSV has columns in a different order.

---

## `src/models/evaluate.py` — Metrics and Confusion Matrix

**Responsibility:** load the saved model, predict on test data, print classification
report, and save a confusion matrix PNG.

### Metrics computed

```python
acc = accuracy_score(y, y_pred)
roc = roc_auc_score(y, y_prob)
print(classification_report(y, y_pred, target_names=["benign", "malicious"]))
```

- **Accuracy**: fraction of sessions correctly classified. Misleading with class
  imbalance but included for completeness.
- **ROC-AUC**: area under the receiver operating characteristic curve, using
  `y_prob` (probability of class 1 from `predict_proba`). Threshold-independent
  measure of discrimination ability.
- **Classification report**: per-class precision, recall, F1, and support, plus
  macro/weighted averages.

### Confusion matrix

```python
cm = confusion_matrix(y, y_pred)
```

Row = true class, column = predicted class. For binary classification:
- `cm[0,0]`: true negatives (benign correctly classified)
- `cm[0,1]`: false positives (benign classified as malicious)
- `cm[1,0]`: false negatives (malicious missed)
- `cm[1,1]`: true positives (malicious correctly detected)

Cell text colour is white if the cell value exceeds half the maximum value, black
otherwise, ensuring readability on both dark and light cells.

---

## `src/models/ablation.py` — Feature Group Ablation

**Responsibility:** measure how much each feature group contributes by removing it
and retraining.

### Feature group definitions

```python
FEATURE_GROUPS = {
    "Group1_EventCounts": ["count_4624", "count_4625", ..., "count_total"],
    "Group2_TimeDelta":   ["td_mean", "td_std", "td_min", "td_max"],
    "Group3_Cardinality": ["n_unique_sources", "n_unique_users", "n_unique_hosts"],
    "Group4_RareFlags":   [],   # populated dynamically
    "Group5_Entropy":     ["seq_entropy"],
}
```

Group 4 is populated at runtime:

```python
flag_cols = [c for c in df.columns if c.startswith("flag_")]
FEATURE_GROUPS["Group4_RareFlags"] = flag_cols
```

This handles the fact that the number of rare event flags is not known at module
import time — it depends on what `identify_rare_events()` found in the training data.

### Ablation procedure

```python
for group_name, group_cols in FEATURE_GROUPS.items():
    remaining = [c for c in train_cols if c not in group_cols]
    idx = [train_cols.index(c) for c in remaining]

    X_tv_sub = X_tv[:, idx]
    X_test_sub = X_test[:, idx]

    clf = RandomForestClassifier(**best_params)
    clf.fit(X_tv_sub, y_tv)
    f1 = f1_score(y_test, clf.predict(X_test_sub), average="macro")
    delta = f1 - f1_full
```

Key design choices:
1. **Same hyperparameters** as the best-performing model — isolates the effect of
   features, not hyperparameters.
2. **Retrain from scratch** with the reduced feature set — not just removing features
   from the existing trees (which would be invalid).
3. **Column index slicing** (`X_tv[:, idx]`) rather than column-name dropping —
   avoids re-creating DataFrames, faster for numpy arrays.
4. **Delta reported as `f1 - f1_full`** — negative means removing the group hurt
   performance; zero means the group was redundant given the others.

### Why Group 4 and 5 show delta=0

As explained in the generator section, 7045 appears in 30% of benign sessions,
making it non-rare. The rare flag list is typically empty, so Group 4 has no
columns to remove. Group 5 (entropy) carries real information (entropy alone
achieves F1≈0.77) but is redundant once Groups 1 and 2 are present — the RF has
already learned everything entropy captures from the count and timing features.

---

## `src/models/baselines.py` — Multi-Model Comparison

**Responsibility:** train five alternative classifiers on the same data and print a
comparison table alongside the saved RF model.

### Class imbalance handling per model

```python
scale_pos = int((y_tv == 0).sum()) / max(int((y_tv == 1).sum()), 1)
```

`scale_pos` is the benign:malicious ratio (≈5). Used as `scale_pos_weight` for
XGBoost — it internally multiplies the gradient of positive-class samples by this
factor, equivalent to overweighting malicious samples.

Each model gets an appropriate imbalance correction:
- LR, DT, SVM: `class_weight="balanced"` (sklearn's mechanism)
- XGBoost: `scale_pos_weight=scale_pos`
- RF: `class_weight="balanced"` (same as train.py)
- Isolation Forest: `contamination=contam` (sets decision threshold to match
  the true malicious fraction)

### Isolation Forest special handling

```python
iso = IsolationForest(contamination=contam, random_state=42, n_jobs=-1)
iso.fit(X_tv)
y_pred_iso = (iso.predict(X_test) == -1).astype(int)
y_score_iso = -iso.score_samples(X_test)
```

Isolation Forest is **unsupervised** — it does not see labels during training.
It learns what "normal" looks like and flags anomalies. `contamination` tells it
what fraction of the training data to treat as anomalous (used for the decision
threshold, not for label supervision).

`iso.predict()` returns -1 for anomalies and +1 for normal. Converting `-1 → 1`
and `+1 → 0` maps to the malicious/benign convention.

`-iso.score_samples(X_test)` gives the anomaly score: higher value = more anomalous.
Negating because `score_samples` returns negative values for anomalies (lower
means more anomalous in sklearn convention). `roc_auc_score` needs higher values
to correspond to the positive class (malicious), so we negate.

### SVM probability scores

```python
if hasattr(clf, "predict_proba"):
    y_prob = clf.predict_proba(X_test)[:, 1]
else:
    y_prob = clf.decision_function(X_test)
```

SVM with `probability=True` enables `predict_proba` through Platt scaling
(cross-validated logistic regression on the decision function). The fallback to
`decision_function` handles other future classifiers that may not have `predict_proba`.

---

## `src/models/multiseed_eval.py` — Multi-Seed Stability Evaluation

**Responsibility:** run the entire pipeline from data generation through evaluation
N times, each with a different random seed, and report mean ± std.

### Why this matters

A single train/test split can be lucky or unlucky. With a 5:1 class ratio and
15% test set (≈150 malicious sessions), random variation in which sessions land in
the test set can meaningfully shift F1. Multi-seed evaluation quantifies this
variance.

### Pipeline per seed

```python
for seed in range(n_seeds):
    log_path = str(raw_dir / f"logs_seed{seed}.csv")
    seed_proc  = proc_dir / f"seed{seed}"
    seed_model = model_dir / f"seed{seed}"

    generate(n_benign, n_malicious, log_path, seed=seed)
    preprocess(str(log_path), str(seed_proc))
    engineer(str(seed_proc), str(seed_proc))
    train(str(seed_proc), str(seed_model))
```

Each seed regenerates the **entire dataset** (generator uses the seed for all its
random choices) and retrains from scratch. This is stronger than just varying the
train/test split: it also varies the specific sessions generated, the session-level
feature values, and the RF random state.

`engineer` writes features to the same directory as processed CSVs (`seed_proc`).
This is intentional — `str(seed_proc)` is passed as both input and output, so
`train_features.csv`, `val_features.csv`, and `test_features.csv` sit alongside
`train.csv`, `val.csv`, `test.csv` in the per-seed directory.

### Summary statistics

```python
df = pd.DataFrame(all_results)
metrics = ["precision", "recall", "f1_macro", "roc_auc"]
summary = {m: (df[m].mean(), df[m].std()) for m in metrics}
```

Reports mean and standard deviation across all seeds. A small standard deviation
(≤0.001 for F1) confirms the result is not a statistical artifact.

---

## `pyproject.toml` — Project Configuration

```toml
[project]
requires-python = ">=3.11"
dependencies = [
    "pandas>=2.0", "numpy>=1.25", "scikit-learn>=1.4",
    "scipy>=1.11", "graphviz>=0.20", "click>=8.1",
    "matplotlib>=3.8", "joblib>=1.3", "xgboost>=3.2.0",
]
```

**Why Python 3.11+?** The code uses the `list[int] | None` union type hint syntax,
which requires Python 3.10+. 3.11 adds performance improvements to the interpreter
that benefit the multi-seed evaluation loop.

**Dependency notes:**
- `scipy` is required for `scipy.stats.entropy` in the feature engineer. Entropy
  could be computed manually, but scipy's implementation handles numerical edge cases.
- `graphviz` is a dependency for figure-generation scripts in `docs/*/figs/`.
- `xgboost` is only used in `baselines.py`, not in the main pipeline.
- `joblib` is used for model serialisation (`joblib.dump/load`). It is more reliable
  than `pickle` for scikit-learn objects because it handles large numpy arrays
  (stored as memory-mapped files in the pickle protocol).

```toml
[tool.black]
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I"]
```

`ruff` rules: `E` (pycodestyle errors), `F` (pyflakes — unused imports, undefined
names), `I` (isort — import ordering). `W` (warnings) and `C` (convention) are
intentionally excluded to avoid over-aggressive reformatting.

---

## Data Flow Summary

```
generator.py           preprocessor.py        engineer.py
────────────           ───────────────        ───────────
n_benign=5000  ──────► train.csv    ─────────► train_features.csv (4200 sessions × 24+ cols)
n_malicious=1000        val.csv     ─────────► val_features.csv   ( 900 sessions × 24+ cols)
seed=42       ──────►  test.csv     ─────────► test_features.csv  ( 900 sessions × 24+ cols)
logs.csv
(89,288 rows)

train.py                evaluate.py
────────────            ───────────
train_features.csv ───► best_model.pkl ───► confusion_matrix.png
val_features.csv                           metrics to stdout

ablation.py             baselines.py        multiseed_eval.py
────────────            ────────────        ─────────────────
best_model.pkl + ──────► F1 delta table     Runs all 4 steps
*_features.csv          best_model.pkl +    above N times with
                        *_features.csv ───► different seeds,
                        ► comparison table  reports mean±std
```

---

## Complete CLI Reference

```
uv run python -m src generate \
    --n-benign 5000 --n-malicious 1000 \
    --output data/raw/logs.csv --seed 42

uv run python -m src preprocess \
    --input data/raw/logs.csv \
    --output data/processed/

uv run python -m src featurize \
    --input data/processed/ \
    --output data/processed/

uv run python -m src train \
    --data data/processed/ \
    --output models/

uv run python -m src evaluate \
    --model models/best_model.pkl \
    --data data/processed/test_features.csv \
    --output models/

uv run python -m src baselines \
    --model models/best_model.pkl \
    --data data/processed/

uv run python -m src multiseed \
    --n-benign 5000 --n-malicious 1000 --n-seeds 5 \
    --work-dir data/multiseed/ \
    --output data/multiseed/results.csv
```
