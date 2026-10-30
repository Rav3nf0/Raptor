import re
from abc import ABC, abstractmethod


ACCOUNT_ID = re.compile(r"(?<!\d)(\d{2})\d{7}(\d{3})(?!\d)")


def mask_ids(obj):
    """Mask 12-digit numbers (AWS account IDs) everywhere in a finding: they are shown to
    analysts in /shadow, and Aadhaar-format numbers trip the Netskope DLP proxy in between."""
    if isinstance(obj, str):
        return ACCOUNT_ID.sub(r"\1…\2", obj)
    if isinstance(obj, list):
        return [mask_ids(x) for x in obj]
    if isinstance(obj, dict):
        return {k: mask_ids(v) for k, v in obj.items()}
    return obj


def kql_list(items) -> str:
    return ", ".join(f'"{i}"' for i in items)


def kql_shape(expr: str, length: int = 160) -> str:
    """KQL expression: `expr` lower-cased with its per-machine parts (URL paths, user profile
    directory, GUIDs, digits) normalised, so the same command on two devices compares equal. Used to
    judge a command by how many devices ran the same thing, instead of by a keyword."""
    return ("substring(replace_regex(replace_regex(replace_regex(replace_regex(tolower(" + expr + "), "
            # a URL compares by scheme + host: every link has its own path and query
            r'@"(https?://[^/\s""]+)[^\s""]*", @"\1"), '
            r'@"(c:\\users\\|/users/)[^\\/]+", "<userdir>"), '
            r'@"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "<guid>"), '
            r'@"[0-9]+", "#"), 0, ' + str(length) + ")")


MASS_HISTORY_DAYS = 14


def kql_fleet(source: str, key: str, max_fleet_devices: int, history_days: int,
              mass_history_days: int = MASS_HISTORY_DAYS) -> str:
    """KQL tabular expression over `source` (rows since windowEnd - mass_history_days, with
    DeviceId and Timestamp): per `key`, whether it qualifies as
      rare — on at most `max_fleet_devices` devices over `history_days`; or
      new and widespread — never seen in the `mass_history_days` before today, and already
      on more than `max_fleet_devices` devices today (Mass = true).
    Rarity alone is blind to something pushed to many machines at once — a compromised
    RMM/MDM or GPO, a poisoned package — which looks exactly like fleet-standard automation.
    What separates the two is that automation was also there last week."""
    return f"""{source}
            | summarize FleetDevices = dcountif(DeviceId, Timestamp >= windowEnd - {history_days}d),
                        PriorDevices = dcountif(DeviceId, Timestamp < windowStart)
                by {key}
            | where FleetDevices <= {max_fleet_devices} or PriorDevices == 0
            | extend Mass = FleetDevices > {max_fleet_devices}"""


def mass_summary(r: dict) -> str:
    devices = r.get("Devices") or []
    return (f"NEW to the fleet today on {r.get('FleetDevices', '?')} device(s), never seen in the "
            f"previous {MASS_HISTORY_DAYS} days — a push to many machines at once"
            + (f" ({', '.join(str(d) for d in devices[:5])}" + (", …" if len(devices) > 5 else "") + ")"
               if devices else ""))


class Detector(ABC):
    name: str = "base"
    mitre_techniques: list[str] = []
    severity: str = "low"
    cadence_minutes: int = 60
    query_name: str = ""  # filename (minus .csv) in mock mode

    @abstractmethod
    def kql(self, lookback_hours: int) -> str: ...

    @abstractmethod
    def to_findings(self, rows: list[dict]) -> list[dict]: ...

    async def fetch(self, defender, lookback_hours: int = 24) -> list[dict]:
        """Rows for to_findings. Most detectors are one MDE advanced-hunting query; the cloud
        detectors override this to query the Sentinel workspace, or to join it with MDE."""
        return await defender.hunt(self.query_name, kql=self.kql(lookback_hours=lookback_hours))

    def should_persist(self, finding: dict) -> bool:
        """Whether a finding becomes a /shadow row. A detector can compute findings that only
        feed the behaviour score (shadow_hunter.behavior) without each being a row a person
        has to read; the default persists everything."""
        return True
