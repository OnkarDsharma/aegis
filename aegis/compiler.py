"""Cross-tool security control compiler (PRD FR-35, FR-16; Differentiation #7).

A proven :class:`~aegis.blueteam.Fix` says *what* to change in the graph (drop an
edge, neutralize a weakness). This module compiles that intent into the concrete,
tool-specific control changes that realize it across the stack the asset actually
lives on - a firewall/security-group rule, a Kubernetes NetworkPolicy, an IAM or
RBAC edit, a WAF virtual patch, an IdP session revocation, plus a SIEM detection
for the newly-blocked behaviour - instead of leaving the operator to translate a
recommendation by hand.

Each :class:`ControlChange` carries a rendered artifact (the actual rule / policy
/ manifest) and a rollback, so the output is reviewable and reversible. Nothing is
pushed to any live system here: compilation produces the change set that a human
(or, for low-risk tiers, the auto-remediation gate) then applies. The platform is
chosen from the target asset's type/environment, so the same fix compiles to AWS,
Kubernetes or OT controls as appropriate (the cross-tool part).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .blueteam import Fix
from .graph import AttackGraph
from .model import NodeKind, node_id


@dataclass
class ControlChange:
    tool: str                 # e.g. aws-security-group, kubernetes, keycloak, modsecurity, splunk
    platform: str             # firewall | cloud | kubernetes | identity | waf | siem | ot | secrets
    action: str               # short imperative, e.g. "deny 0.0.0.0/0 to 5432"
    summary: str
    artifact: str             # the concrete rule / manifest / command this emits
    rollback: str
    applies_to: str

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class CompiledRemediation:
    fix_id: str
    fix_type: str
    title: str
    target: str
    approval_tier: str
    changes: list[ControlChange] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({c.tool for c in self.changes})

    def as_dict(self) -> dict[str, Any]:
        return {
            "fix_id": self.fix_id, "fix_type": self.fix_type, "title": self.title,
            "target": self.target, "approval_tier": self.approval_tier,
            "tools": self.tools, "changes": [c.as_dict() for c in self.changes],
        }


class ControlCompiler:
    """Compile a proven fix into concrete per-tool control changes."""

    def __init__(self) -> None:
        self._handlers: dict[str, Callable[[Fix, dict[str, Any]], list[ControlChange]]] = {
            "segmentation": self._segmentation,
            "cloud-firewall": self._segmentation,
            "web-firewall": self._waf,
            "modsecurity-waf": self._waf,
            "credential": self._rotate_secret,
            "bucket-policy": self._bucket_policy,
            "metadata-guard": self._metadata_guard,
            "k8s-networkpolicy": self._network_policy,
            "pod-security": self._pod_security,
            "rbac-tighten": self._rbac,
            "ot-protocol-gateway": self._ot_gateway,
            "identity-hygiene": self._identity_hygiene,
        }

    def compile(self, fix: Fix, graph: AttackGraph) -> CompiledRemediation:
        asset = graph.nodes.get(node_id(NodeKind.ASSET, fix.target))
        ctx = {
            "target": fix.target,
            "asset_type": str(asset.props.get("asset_type", "server")) if asset else "server",
            "environment": str(asset.props.get("environment", "range")) if asset else "range",
            "provider": str(asset.props.get("provider", "")) if asset else "",
            "fix": fix,
        }
        handler = self._handlers.get(fix.fix_type, self._generic)
        changes = handler(fix, ctx)
        changes.append(self._siem(fix, ctx))  # always add a detection for the blocked behaviour
        return CompiledRemediation(fix.fix_id, fix.fix_type, fix.title, fix.target, fix.approval_tier, changes)

    def compile_all(self, fixes: list[Fix], graph: AttackGraph) -> list[CompiledRemediation]:
        return [self.compile(f, graph) for f in fixes]

    # --------------------------------------------------------------- handlers
    def _segmentation(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        atype = ctx["asset_type"]
        if atype.startswith(("aws", "gcp", "azure")) or ctx["environment"] == "production" and "cloud" in atype:
            return [ControlChange(
                "aws-security-group", "cloud", f"deny inbound to {t}",
                f"Replace the 0.0.0.0/0 ingress rule on {t} with least-privilege source ranges.",
                f"aws ec2 revoke-security-group-ingress --group-id <sg-{t}> --protocol tcp --cidr 0.0.0.0/0",
                f"Re-add the previous ingress rule to <sg-{t}>.", t)]
        if atype == "pod":
            return self._network_policy(fix, ctx)
        if atype.startswith("ot"):
            return self._ot_gateway(fix, ctx)
        return [ControlChange(
            "iptables", "firewall", f"drop route to {t}",
            f"Block the direct network path to {t} at the host/zone firewall.",
            f"iptables -A FORWARD -d {t} -j DROP   # remove the flat path surfaced by AEGIS",
            f"iptables -D FORWARD -d {t} -j DROP", t)]

    def _waf(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "modsecurity", "waf", f"virtual-patch {t}",
            f"Deploy a ModSecurity virtual patch in front of {t} to block injection payloads.",
            'SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,'
            f'msg:\'AEGIS virtual patch for {t}\'"',
            "Remove rule id:1001 and the ModSecurity sidecar.", t)]

    def _rotate_secret(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "vault", "secrets", f"rotate secret for {t}",
            f"Rotate {t}'s credential and move it to the secrets manager; update consumers.",
            f"vault kv put secret/{t}/db password=$(openssl rand -base64 24)   # value never leaves the manager",
            f"vault kv rollback -version=<n> secret/{t}/db", t)]

    def _bucket_policy(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "aws-s3", "cloud", f"block public access on {t}",
            f"Enable Block Public Access and remove the public-read bucket policy on {t}.",
            f"aws s3api put-public-access-block --bucket {t} "
            "--public-access-block-configuration BlockPublicAcls=true,RestrictPublicBuckets=true",
            f"Restore the previous public-access-block configuration on {t}.", t)]

    def _metadata_guard(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "cloud-compute", "cloud", f"enforce IMDSv2 on {t}",
            f"Require IMDSv2 and restrict the metadata hop limit on {t}.",
            f"aws ec2 modify-instance-metadata-options --instance-id <{t}> "
            "--http-tokens required --http-put-response-hop-limit 1",
            f"Restore the previous metadata options on {t}.", t)]

    def _network_policy(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        manifest = (
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"
            f"metadata:\n  name: aegis-isolate-{t}\nspec:\n"
            f"  podSelector:\n    matchLabels:\n      app: {t}\n"
            "  policyTypes: [Ingress]\n  ingress: []   # default-deny; add only required sources"
        )
        return [ControlChange(
            "kubernetes", "kubernetes", f"NetworkPolicy isolate {t}",
            f"Apply a default-deny NetworkPolicy so only required workloads reach {t}.",
            manifest, f"kubectl delete networkpolicy aegis-isolate-{t}", t)]

    def _pod_security(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "kubernetes", "kubernetes", f"restrict privileges on {t}",
            f"Enforce the restricted Pod Security Standard on {t}'s namespace and drop privileged/hostPath.",
            "kubectl label namespace <ns> pod-security.kubernetes.io/enforce=restricted --overwrite",
            "Set the namespace back to its previous pod-security level.", t)]

    def _rbac(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "kubernetes-rbac", "identity", f"remove cluster-admin binding near {t}",
            "Replace the cluster-admin ClusterRoleBinding on the ServiceAccount with a least-privilege Role.",
            "kubectl delete clusterrolebinding <deploy-bot-cluster-admin>   # then bind a scoped Role",
            "Recreate the previous binding (not recommended).", t)]

    def _ot_gateway(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "ot-firewall", "ot", f"protocol gateway in front of {t}",
            f"Put a protocol-aware gateway / data diode in front of {t} so only authenticated, "
            "allow-listed Modbus function codes reach it.",
            f"otfw policy add --dst {t} --proto modbus --require-auth --allow fc=3,4 --deny-default",
            f"Remove the protocol gateway policy for {t}.", t)]

    def _identity_hygiene(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "keycloak", "identity", f"revoke cached sessions on {t}",
            f"Revoke cached sessions and disable credential caching for {t} at the IdP.",
            "kcadm.sh update users/<id>/logout -r aegis   # plus disable offline-session caching",
            "Re-enable session caching (not recommended).", t)]

    def _siem(self, fix: Fix, ctx: dict[str, Any]) -> ControlChange:
        t = ctx["target"]
        return ControlChange(
            "sigma-siem", "siem", f"detect attempts against {t}",
            f"Deploy a detection so any future attempt on the path AEGIS just closed on {t} is alerted.",
            "title: AEGIS post-remediation watch\n"
            f"detection:\n  selection:\n    target: {t}\n    fix_applied: {fix.fix_type}\n  condition: selection",
            "Retire the detection rule.", t)

    def _generic(self, fix: Fix, ctx: dict[str, Any]) -> list[ControlChange]:
        t = ctx["target"]
        return [ControlChange(
            "config-management", "config", f"apply {fix.fix_type} to {t}",
            fix.predicted_impact or f"Apply {fix.fix_type} to {t}.",
            f"# AEGIS: apply '{fix.fix_type}' to {t} via configuration management",
            fix.rollback or f"Revert {fix.fix_type} on {t}.", t)]
