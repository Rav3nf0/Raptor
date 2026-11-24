from shadow_hunter.detectors.base import Detector
from shadow_hunter.detectors.cloud import CloudSessionSplitDetector, EdrSilentActiveDetector
from shadow_hunter.detectors.control_bypass import ControlBypassDetector
from shadow_hunter.detectors.defender_exclusions import DefenderExclusionsDetector
from shadow_hunter.detectors.edge_attacks import EdgeAttacksDetector
from shadow_hunter.detectors.eks_audit import EksAuditDetector
from shadow_hunter.detectors.encoded_powershell import EncodedPowerShellDetector
from shadow_hunter.detectors.exfil_patterns import ExfilPatternsDetector
from shadow_hunter.detectors.lolbin_abuse import LOLBinAbuseDetector
from shadow_hunter.detectors.package_installs import PackageInstallsDetector
from shadow_hunter.detectors.rds_audit import RdsAuditDetector
from shadow_hunter.detectors.rare_persistence import RarePersistenceDetector
from shadow_hunter.detectors.rare_domains import RareDomainsDetector
from shadow_hunter.detectors.remote_logons import RemoteLogonsDetector
from shadow_hunter.detectors.ssh_backdoor import SshBackdoorDetector
from shadow_hunter.detectors.suspicious_parent_child import SuspiciousParentChildDetector
from shadow_hunter.detectors.upwind import UpwindThreatsDetector

DETECTORS: list[Detector] = [
    # High severity — run every 30 min
    SuspiciousParentChildDetector(),
    EncodedPowerShellDetector(),
    ExfilPatternsDetector(),
    DefenderExclusionsDetector(),
    # Medium/high — run every 60 min
    RareDomainsDetector(),
    LOLBinAbuseDetector(),
    RarePersistenceDetector(),
    SshBackdoorDetector(),
    ControlBypassDetector(),
    # PackageInstallsDetector() — paused 2026-10-01: even trimmed, its run got the UAT pod OOM-killed
    # (256 MiB limit, ~160 MiB used at idle). Re-enable once the pod has >=1 GiB.
    # Medium — run every 30 min
    RemoteLogonsDetector(),
    # Sentinel workspace (CloudTrail / Entra sign-ins), every 3-6 h
    CloudSessionSplitDetector(),
    EdrSilentActiveDetector(),
    # Upwind CNAPP mirror (no MDE query), hourly
    UpwindThreatsDetector(),
    # Cloudflare edge via VictoriaLogs (no MDE query), every 30 min
    EdgeAttacksDetector(),
    # EKS prod API audit and RDS (Aurora) audit via VictoriaLogs, every 30 / 60 min
    EksAuditDetector(),
    RdsAuditDetector(),
]

__all__ = ["Detector", "DETECTORS"]
