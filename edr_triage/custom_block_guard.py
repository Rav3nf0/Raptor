"""CustomEnterpriseBlock: close what L2 always closes — our own AnyDesk block rule doing its job.

`'CustomEnterpriseBlock' malware was detected` is Defender enforcing OUR custom indicator
(detectionSource CustomerTI) against AnyDesk. Over 90 days to 2026-10-05 every one of the 81
closed tickets was AnyDesk, and every one was closed by L2 with the same note: "custom rule
in Microsoft EDR to detect and quarantine the file … detected and prevented hence no
further action required … true positive" — walked through the full incident chain to
Closed. RAPTOR mirrors exactly that, and only where the evidence shows nothing left to do:

  * the detection is our custom indicator (CustomerTI + CustomEnterpriseBlock), and the
    alert is not "An active … was blocked" (that one was running);
  * every evidence entity is a FILE — a process entity means something executed;
  * every file is an AnyDesk artefact: by name or path, or by SHA-256 equal to a file
    already seen named as AnyDesk (KNOWN_ANYDESK_SHA256) — a renamed copy in the Recycle
    Bin ($R9G29E8.exe) or a browser-cache copy (f_00011f) is the same file. A file that is
    none of these — a Takeout zip (DEMO-115552), an unseen $RBG7HEC.exe — stays with a person;
  * a file only "Detected" (not Blocked/Prevented) is closed too, since 2026-10-12 (L2's
    decision): over 112 tickets Jun–Oct, 26 the rule left for a person were exactly that —
    AnyDesk files on disk, never executed — and L2 closed every one as a true positive with
    "no further action". It may still be on the laptop, so the close says where, and the
    ticket is labelled anydesk-on-disk for follow-up.

This is a TRUE POSITIVE close (status Closed), as L2 records it; never False Positive.
"""
from __future__ import annotations

import re

LABEL = "raptor-custom-block"
CLOSE_ROUTE = ["Assigned", "Event Analysis", "In Progress", "Containment", "Eradication",
               "Recovery", "RCA", "Resolved", "Closed"]
_TITLE = re.compile(r"^'CustomEnterpriseBlock' malware was (detected|prevented|blocked)$", re.I)
_INERT = {"blocked", "prevented"}
ON_DISK_LABEL = "anydesk-on-disk"
# SHA-256 of every file seen NAMED as AnyDesk in this rule's evidence, Jun–Oct 2026 (112 tickets).
KNOWN_ANYDESK_SHA256 = frozenset({
    "0edc44af859fbd491246b590547af88e922acf0b2adbd5c7a8e8516ec41790ae",
    "1c702e234542e2bb53e45211cc3ae4426a5088de9510dae58a9ff8b7a65e294f",
    "28a4f2209dd3d82874691b1b0f9fc594f2aa3ba1c877154ccb9465a847c4a4c5",
    "3aa636e7660be17f841b7f0e380f93fb94f25c62d9100758b1d480cbb863db9d",
    "467d1395b61d4b886329571b564fb21db01639acd2799439646c85b9aeaec175",
    "5214e8ff8454c715b10b448e496311b4ff18306ecf9cbb99a97eb0076304ce9a",
    "63d66742e70ab882884c899c89855451143748be29ccdf1ce485b2f685a4cc1c",
    "64547b7a4a9de8af79ff0eefadde2aed10c17f9d8f9a2465c0110c848d85317a",
    "71b071c03d010980382cd3da10166945364ad218c48902e24a053fe7235618bc",
    "76d64a03f9b0347800c677d79a4c6d7b7a109022dc6c10a11922b79db2fa96f0",
    "7f8671134a3b033b1ada9a36effc8383c303f448ccd7d9ba68da941111f09326",
    "8cd552392bb25546ba58e73d63c4b7c290188ca1060f96c8abf641ae9f5a8383",
    "a209e3f7645ed94517ebbfc27e9c7abf90cb3564b662a0a2585ab3b226766fee",
    "b88f36d7a9c54c49e429c600f8eeb92394665564d4be43290eb6e0df2488e306",
    "cba7c721b76bb7245cd0f1fbfdf85073d57512ead2593050cad12ce76886ac33",
    "d6795659b634e86067f39e413fe7fdee8ebd165407a63e26149fa93bdcd6e4af",
    "d7b9f1141c649c08254a4978f98211a5ab3b10591693fcf271409e36beae2933",
    "e978db3dd1b472984b902a8f33e6bee56035190981d0ba5b57bad44c5b302bb9",
    "ef2393586230a76e15b548659ca74df032048e0bf7633acb4ad6242759ea45ad",
    "fa0f2e683c50d4908381e6ef16edcec29cc3f1d225b63de58f83d1c9bd854ff9",
    "fc19f3275d02764cf249dc6fe8962e06b83a4f5769cc369bc4f77b90c567df18",
})


def applies(alert_name: str) -> bool:
    return bool(_TITLE.match((alert_name or "").strip()))


def _shadow(path: str) -> bool:
    return "harddiskvolumeshadowcopy" in (path or "").lower()


def decide(alert: dict, evidence: list[dict]) -> tuple[bool, str]:
    """(close, reason). Pure; reads the MDE alert and its raw evidence list."""
    alert = alert or {}
    if not applies(alert.get("title") or ""):
        return False, "not a CustomEnterpriseBlock detected/prevented alert"
    if (alert.get("detectionSource") or "") != "CustomerTI" or \
            "customenterpriseblock" not in (alert.get("threatName") or "").lower():
        return False, "not our custom indicator"
    if not evidence:
        return False, "no evidence to check"
    other = sorted({e.get("entityType") or "?" for e in evidence} - {"File"})
    if other:
        return False, f"evidence includes {', '.join(other)}, not only files"
    for e in evidence:
        name, path = e.get("fileName") or "", e.get("filePath") or ""
        if not is_anydesk(e):
            return False, f"{name or path or 'a file'} is not a known AnyDesk artefact"
    disk = on_disk(evidence)
    if disk:
        return True, (f"{len(evidence)} AnyDesk file(s), none executed; {len(disk)} only "
                      "detected (still on disk)")
    return True, f"{len(evidence)} AnyDesk file(s), all blocked or inert in a shadow copy"


def is_anydesk(e: dict) -> bool:
    if "anydesk" in ((e.get("fileName") or "") + " " + (e.get("filePath") or "")).lower():
        return True
    return (e.get("sha256") or "").lower() in KNOWN_ANYDESK_SHA256


def on_disk(evidence: list[dict]) -> list[dict]:
    """Files Defender only detected: not blocked, not inside a read-only shadow copy."""
    return [e for e in evidence or [] if not (_shadow(e.get("filePath") or "")
            or (e.get("detectionStatus") or "").lower() in _INERT)]


def comment(alert: dict, evidence: list[dict]) -> str:
    files = sorted({e.get("fileName") or "?" for e in evidence})
    host = alert.get("computerDnsName") or "the host"
    disk = on_disk(evidence)
    head = ("*RAPTOR closed this as a true positive: our custom block rule worked.*\n\n"
            f"Microsoft Defender's custom indicator for AnyDesk (CustomEnterpriseBlock) fired on "
            f"*{host}*: {', '.join(files[:5])}" + (f" and {len(files) - 5} more" if len(files) > 5 else "")
            + ". No process was involved — nothing ran.")
    if not disk:
        body = (" Every file is either blocked by Defender or a leftover inside a read-only shadow "
                "copy — detected and prevented, no further action required, matching how L2 has "
                "closed every such ticket.")
    else:
        paths = sorted({(e.get("filePath") or "?") + "\\" + (e.get("fileName") or "?") for e in disk})
        body = (f"\n\n*Still on disk:* Defender only detected {len(disk)} file(s) — not blocked or "
                "removed — so AnyDesk may still be present on this host:\n"
                + "\n".join(f"* {p}" for p in paths[:8])
                + (f"\n* … and {len(paths) - 8} more" if len(paths) > 8 else "")
                + f"\n\nClosed as L2 closes these (no further action); labelled `{ON_DISK_LABEL}` "
                "for follow-up removal.")
    return (head + body + "\n\nReopen this ticket if AnyDesk is actually in use on this host."
            "\n\n[Auto-triaged by RAPTOR]")
