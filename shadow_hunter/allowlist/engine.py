"""Allowlist engine — simple match semantics over two rule sources.

    rules.yaml  — the reviewed baseline, changed through the repo. Read-only at runtime.
    Mongo       — rules added from the /shadow UI when a finding is dismissed
                  (collection shadow_allowlist_rules). Shared by every replica and kept across
                  deploys; the YAML file inside a container is neither — the app runs as two
                  replicas and each deploy replaces the image, so a rule appended to the
                  container's copy was on one pod only and gone at the next deploy.

Supported match keys:
    indicator_contains:   substring match against finding.indicator
    indicator_matches:    regex against finding.indicator
    indicator_startswith: prefix match
    remote_ip_in:         list of IPs; matches if any finding.raw.SourceIPs entry is in it
    initiating_process:   matches if any InitiatingProcesses entry equals (case-insensitive)
    account_equals:       finding.account_name == value
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass
class AllowlistRule:
    name: str
    detector: str = ""  # empty = all detectors
    match: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    owner: str = ""
    source: str = "repo"      # "repo" (rules.yaml) | "ui" (Mongo)
    created_at: str = ""

    def applies_to(self, finding: dict) -> bool:
        if self.detector and finding.get("detector") != self.detector:
            return False

        indicator = str(finding.get("indicator") or "")
        raw = finding.get("raw") or {}
        source_ips = raw.get("SourceIPs") or []
        procs = raw.get("InitiatingProcesses") or []

        m = self.match
        if "indicator_contains" in m and m["indicator_contains"] not in indicator:
            return False
        if "indicator_startswith" in m and not indicator.startswith(m["indicator_startswith"]):
            return False
        if "indicator_matches" in m:
            try:
                if not re.search(m["indicator_matches"], indicator):
                    return False
            except re.error:
                import logging
                logging.getLogger(__name__).warning(
                    "Malformed regex in allowlist rule '%s': %s",
                    self.name, m["indicator_matches"],
                )
                return False
        if "remote_ip_in" in m:
            if not any(ip in m["remote_ip_in"] for ip in source_ips):
                return False
        if "initiating_process" in m:
            wanted = m["initiating_process"].lower()
            if not any(p.lower() == wanted for p in procs if isinstance(p, str)):
                return False
        if "account_equals" in m:
            if finding.get("account_name") != m["account_equals"]:
                return False
        return True


class AllowlistEngine:
    def __init__(self, rules: list[AllowlistRule]) -> None:
        self.rules = rules

    @classmethod
    def load(cls, path: Path) -> "AllowlistEngine":
        import logging
        logger = logging.getLogger(__name__)
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except FileNotFoundError:
            logger.warning("Allowlist file not found: %s — running with no rules", path)
            return cls([])
        except yaml.YAMLError as exc:
            logger.error("Malformed allowlist YAML (%s): %s — running with no rules", path, exc)
            return cls([])
        rules = []
        for r in data.get("rules", []):
            try:
                rules.append(AllowlistRule(**r))
            except Exception as exc:
                logger.warning("Skipping malformed allowlist rule %r: %s", r, exc)
        return cls(rules)

    def match(self, finding: dict) -> AllowlistRule | None:
        for rule in self.rules:
            if rule.applies_to(finding):
                return rule
        return None

    def annotate(self, findings: list[dict]) -> list[dict]:
        """Tag each finding with allowlisted_by_rule if matched."""
        for f in findings:
            rule = self.match(f)
            # A detector may already have suppressed a finding with a rule a yaml match cannot
            # express (upwind's time-boxed IronWatch window); keep it rather than clear it.
            f["allowlisted_by_rule"] = rule.name if rule else f.get("allowlisted_by_rule", "")
        return findings

    @staticmethod
    def rule_from_finding(finding: dict, reviewer: str, note: str) -> AllowlistRule:
        """Derive a best-effort allowlist rule from a false-positive finding."""
        detector = finding.get("detector", "")
        indicator = str(finding.get("indicator") or "")
        account = finding.get("account_name", "")
        raw = finding.get("raw") or {}
        source_ips = raw.get("SourceIPs") or []

        if detector == "unusual_remote_logons" and indicator:
            # This account on this device only. An account-wide rule hid every later RDP anomaly
            # for the account — the lateral move it would make next included.
            match = {"indicator_matches": f"^{re.escape(indicator)}$"}
        elif account and detector in ("unusual_remote_logons",):
            match = {"account_equals": account}
        elif source_ips and len(source_ips) == 1:
            match = {"remote_ip_in": source_ips}
        elif indicator:
            match = {"indicator_contains": indicator[:80]}
        else:
            match = {"indicator_contains": ""}

        slug = re.sub(r"[^a-z0-9]+", "-", indicator.lower())[:30].strip("-")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d")
        name = f"fp-{detector[:20]}-{slug}-{ts}" if slug else f"fp-{detector[:20]}-{ts}"

        return AllowlistRule(
            name=name,
            detector=detector,
            match=match,
            reason=note or f"False positive: {indicator[:80]}",
            owner=reviewer,
        )

    @classmethod
    async def load_all(cls, path: Path) -> "AllowlistEngine":
        """rules.yaml plus the rules added from the UI. A Mongo failure leaves the repo rules
        in force rather than none."""
        import logging
        engine = cls.load(path)
        try:
            docs = await _ui_rules().find({}, {"_id": 0}).sort("created_at", 1).to_list(length=None)
        except Exception:
            logging.getLogger(__name__).exception("Could not load UI allowlist rules — repo rules only")
            return engine
        for d in docs:
            engine.rules.append(AllowlistRule(
                name=d["name"], detector=d.get("detector", ""), match=d.get("match") or {},
                reason=d.get("reason", ""), owner=d.get("owner", ""), source="ui",
                created_at=d.get("created_at", "")))
        return engine

    @staticmethod
    async def add_rule(rule: AllowlistRule) -> AllowlistRule | None:
        """Store a UI rule in Mongo under a unique name. Refuses a rule whose match is empty or
        has an empty value: `indicator_contains: ""` matches every finding of the detector."""
        if not rule.match or any(v in ("", None, [], {}) for v in rule.match.values()):
            return None
        coll = _ui_rules()
        await coll.create_index("name", unique=True)
        base, n = rule.name, 1
        while await coll.find_one({"name": rule.name}):
            n += 1
            rule.name = f"{base}-{n}"
        rule.source, rule.created_at = "ui", datetime.now(timezone.utc).isoformat()
        await coll.insert_one({"name": rule.name, "detector": rule.detector, "match": rule.match,
                               "reason": rule.reason, "owner": rule.owner, "created_at": rule.created_at})
        return rule

    @staticmethod
    async def delete_rule(name: str) -> dict:
        """Remove a UI rule and put the unreviewed findings it was hiding back in the queue.
        Repo rules are not deletable here — they change through rules.yaml."""
        from shadow_hunter.models import Finding
        res = await _ui_rules().delete_one({"name": name})
        if not res.deleted_count:
            return {"deleted": False, "restored": 0}
        upd = await Finding.get_pymongo_collection().update_many(
            {"allowlisted_by_rule": name, "reviewed_at": None}, {"$set": {"allowlisted_by_rule": ""}})
        return {"deleted": True, "restored": upd.modified_count}

    @staticmethod
    async def apply_to_open(rule: AllowlistRule, exclude_id: str | None = None) -> int:
        """Hide the unreviewed findings a new rule matches, so dismissing one finding also
        clears its siblings already in the queue, not just future ones."""
        from shadow_hunter.models import Finding
        coll = Finding.get_pymongo_collection()
        query = {"reviewed_at": None, "legacy": {"$ne": True}, "allowlisted_by_rule": ""}
        if exclude_id:  # the finding being dismissed carries the review, not the rule
            query["_id"] = {"$ne": exclude_id}
        if rule.detector:
            query["detector"] = rule.detector
        ids = [d["_id"] for d in await coll.find(query).to_list(length=None) if rule.applies_to(d)]
        if not ids:
            return 0
        res = await coll.update_many({"_id": {"$in": ids}}, {"$set": {"allowlisted_by_rule": rule.name}})
        return res.modified_count


UI_RULES_COLL = "shadow_allowlist_rules"


def _ui_rules():
    from shadow_hunter.models import Finding
    return Finding.get_pymongo_collection().database[UI_RULES_COLL]
