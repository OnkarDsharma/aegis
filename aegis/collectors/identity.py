"""Directory / IdP collector - Keycloak (PRD FR-1, FR-6, FR-33).

Identities, the IdP that issues them, and what their roles let them do on
range assets. Reads either a realm export JSON (offline / CI) or the live
Keycloak admin REST API.

Role and user attributes link identities to assets:

    role attribute  aegis.admin_of  = <asset>   -> identity ADMIN_OF asset (app_admin)
    role attribute  aegis.login_to  = <asset>   -> identity CAN_LOGIN asset (foothold)
    user attribute  aegis.session_on = <asset>  -> credentials exposed on asset (SESSION_ON)

Every identity also TRUSTS the IdP asset: controlling the IdP means
controlling every identity it issues (a trust-boundary edge).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx

from ..model import EdgeKind, Level, Node, NodeKind, Observation, node_id


def realm_from_file(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw = Path(path).read_text(encoding="utf-8")
    return json.loads(raw), {"source": str(path), "sha256": hashlib.sha256(raw.encode()).hexdigest()}


def realm_from_api(base_url: str, realm: str, admin_user: str, admin_password: str, timeout: float = 10.0) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fetch the same shape as a realm export via the admin REST API."""
    with httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout) as client:
        token = client.post(
            "/realms/master/protocol/openid-connect/token",
            data={"grant_type": "password", "client_id": "admin-cli", "username": admin_user, "password": admin_password},
        )
        token.raise_for_status()
        client.headers["Authorization"] = f"Bearer {token.json()['access_token']}"
        roles = client.get(f"/admin/realms/{realm}/roles", params={"briefRepresentation": "false"}).json()
        users = client.get(f"/admin/realms/{realm}/users", params={"briefRepresentation": "false", "max": 1000}).json()
        for user in users:
            mapped = client.get(f"/admin/realms/{realm}/users/{user['id']}/role-mappings/realm").json()
            user["realmRoles"] = [r["name"] for r in mapped]
    payload = {"realm": realm, "roles": {"realm": roles}, "users": users}
    blob = json.dumps(payload, sort_keys=True)
    return payload, {"source": f"{base_url}/admin/realms/{realm}", "sha256": hashlib.sha256(blob.encode()).hexdigest()}


def identity_observation(realm: dict[str, Any], evidence: dict[str, Any], idp_asset: str = "keycloak") -> Observation:
    realm_name = str(realm.get("realm", "realm"))
    obs = Observation(collector="keycloak", scope=f"identity:{realm_name}", evidence=evidence)
    idp = node_id(NodeKind.ASSET, idp_asset)
    obs.add_node(Node(idp, NodeKind.ASSET, {"name": idp_asset, "asset_type": "idp"}))

    roles = {r["name"]: r for r in (realm.get("roles") or {}).get("realm", [])}
    for user in realm.get("users") or []:
        if not user.get("enabled", True):
            continue
        username = user.get("username", "")
        is_service = username.startswith("service-account-") or bool(user.get("serviceAccountClientId"))
        iid = node_id(NodeKind.IDENTITY, f"{realm_name}/{username}")
        user_roles = [roles[name] for name in user.get("realmRoles") or [] if name in roles]
        admin_of = {asset for role in user_roles for asset in _attr(role, "aegis.admin_of")}
        login_to = {asset for role in user_roles for asset in _attr(role, "aegis.login_to")}
        obs.add_node(
            Node(
                iid,
                NodeKind.IDENTITY,
                {
                    "name": username,
                    "realm": realm_name,
                    "identity_type": "service" if is_service else "user",
                    "roles": sorted(r["name"] for r in user_roles),
                    "privileged": bool(admin_of),
                    "mfa": "CONFIGURE_TOTP" not in (user.get("requiredActions") or []) and any(
                        c.get("type") == "otp" for c in user.get("credentials") or []
                    ),
                },
            )
        )
        obs.add_edge(iid, idp, EdgeKind.TRUSTS, relation="issued_by")
        for asset in sorted(admin_of):
            obs.add_edge(iid, node_id(NodeKind.ASSET, asset), EdgeKind.ADMIN_OF, level=Level.APP_ADMIN)
        for asset in sorted(login_to):
            obs.add_edge(iid, node_id(NodeKind.ASSET, asset), EdgeKind.CAN_LOGIN, level=Level.FOOTHOLD)
        for asset in _attr(user, "aegis.session_on"):
            obs.add_edge(iid, node_id(NodeKind.ASSET, asset), EdgeKind.SESSION_ON, confidence=0.5)
    return obs


def _attr(obj: dict[str, Any], key: str) -> list[str]:
    value = (obj.get("attributes") or {}).get(key) or []
    return [str(v) for v in (value if isinstance(value, list) else [value])]
