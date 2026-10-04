"""Configuration loading for the MCP gateway.

Everything is driven by a single YAML file (see config.example.yaml).
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(value: str) -> str:
    """Expand ${VAR} / ${VAR:-default} references in config values."""

    def repl(match: re.Match[str]) -> str:
        var, default = match.group(1), match.group(2)
        if var in os.environ:
            return os.environ[var]
        if default is not None:
            return default
        raise ValueError(f"Config references undefined environment variable: {var}")

    return _ENV_PATTERN.sub(repl, value)


def _expand_tree(node: object) -> object:
    if isinstance(node, str):
        return _expand_env(node)
    if isinstance(node, list):
        return [_expand_tree(item) for item in node]
    if isinstance(node, dict):
        return {key: _expand_tree(value) for key, value in node.items()}
    return node


class UserConfig(BaseModel):
    """A local user allowed to log in to the gateway's authorization server."""

    username: str
    # Exactly one of these must be set. `password_hash` is a bcrypt hash
    # (generate with `mcp-gateway hash-password`); `password` is plaintext and
    # only meant for quick local testing.
    password_hash: str | None = None
    password: str | None = None

    @model_validator(mode="after")
    def _check_password(self) -> UserConfig:
        if bool(self.password_hash) == bool(self.password):
            raise ValueError(
                f"User {self.username!r}: set exactly one of 'password_hash' or 'password'"
            )
        return self


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def require_https_url(url: str, field: str) -> str:
    """Reject non-HTTPS identity-provider URLs (loopback is allowed, for local testing)."""
    parsed = urlparse(url)
    if parsed.scheme == "https" and parsed.netloc:
        return url
    if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
        return url
    raise ValueError(f"{field} must be an https:// URL (got {url!r})")


# Entra ID tenant aliases that accept users from more than one tenant.
ENTRA_MULTI_TENANT_ALIASES = frozenset({"common", "organizations", "consumers"})


class OIDCProviderConfig(BaseModel):
    """An external OpenID Connect identity provider users can sign in with.

    ``type: oidc`` is any standards-compliant provider (Keycloak, Authentik,
    Google, Okta, Auth0, ...), located via OIDC discovery from ``issuer``.
    ``type: entra`` is Microsoft Entra ID (Azure AD): the issuer is derived
    from ``tenant_id``, and the tenant-templated issuer of the multi-tenant
    endpoints is validated against the token's ``tid`` claim.

    Signing in with a provider only proves *who* the user is. Who may use the
    gateway is decided by the ``allowed_*`` rules (a user passing any one of
    them is admitted), or ``allow_all_users: true`` to admit everyone the
    provider authenticates.
    """

    type: Literal["oidc", "entra"] = "oidc"
    # Button label on the login page. Defaults to "Microsoft" for Entra, else the provider key.
    display_name: str | None = None

    # type == "oidc": issuer URL; discovery is fetched from
    # <issuer>/.well-known/openid-configuration unless discovery_url is set.
    issuer: str | None = None
    discovery_url: str | None = None

    # type == "entra": directory (tenant) ID or a verified domain. The aliases
    # "organizations" / "common" / "consumers" enable multi-tenant sign-in and
    # then require allowed_tenants.
    tenant_id: str | None = None
    # Entra authority host; override for national clouds
    # (e.g. https://login.microsoftonline.us, https://login.chinacloudapi.cn).
    authority_host: str = "https://login.microsoftonline.com"
    # type == "entra": tenant IDs (the token's `tid` claim) allowed to sign in.
    allowed_tenants: list[str] = Field(default_factory=list)

    client_id: str
    # Omit for a public client (PKCE only), if the provider allows that.
    client_secret: str | None = None
    # How client_secret is presented to the token endpoint. Default: picked from
    # the provider's discovery document (client_secret_basic preferred).
    token_endpoint_auth_method: (
        Literal["client_secret_basic", "client_secret_post", "none"] | None
    ) = None
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    # Extra query parameters for the authorization request (e.g. prompt,
    # domain_hint, login_hint, hd).
    extra_authorize_params: dict[str, str] = Field(default_factory=dict)

    # Claim used as the gateway username. Default: "preferred_username" for
    # Entra, "email" otherwise. Dotted paths address nested claims.
    username_claim: str | None = None
    # Claims holding the user's groups / roles (dotted paths address nested
    # claims, e.g. Keycloak's "realm_access.roles"). Entra emits group object
    # IDs in "groups" and app roles in "roles".
    groups_claim: str = "groups"
    roles_claim: str = "roles"

    # Authorization rules (case-insensitive). A user matching any one is admitted.
    allowed_users: list[str] = Field(default_factory=list)
    # Domain part of the username (e.g. "example.com" admits alice@example.com).
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_groups: list[str] = Field(default_factory=list)
    allowed_roles: list[str] = Field(default_factory=list)
    # Admit every user the provider authenticates. Must be set explicitly;
    # with a public provider (Google, a multi-tenant Entra app, ...) that
    # means *anyone* with an account there.
    allow_all_users: bool = False

    @model_validator(mode="after")
    def _check(self) -> OIDCProviderConfig:
        if self.type == "oidc":
            if not self.issuer:
                raise ValueError("OIDC provider of type 'oidc' requires 'issuer'")
            self.issuer = require_https_url(self.issuer, "issuer")
            if self.tenant_id or self.allowed_tenants:
                raise ValueError("'tenant_id'/'allowed_tenants' only apply to type 'entra'")
        else:
            if not self.tenant_id:
                raise ValueError("OIDC provider of type 'entra' requires 'tenant_id'")
            if self.issuer:
                raise ValueError(
                    "type 'entra' derives the issuer from 'tenant_id'; don't set 'issuer'"
                )
            self.authority_host = require_https_url(
                self.authority_host.rstrip("/"), "authority_host"
            )
            if self.is_multi_tenant and not self.allowed_tenants:
                raise ValueError(
                    f"Entra tenant_id {self.tenant_id!r} admits users from any tenant; "
                    "set 'allowed_tenants' to the tenant IDs that may sign in"
                )
        if self.discovery_url:
            self.discovery_url = require_https_url(self.discovery_url, "discovery_url")
        if "openid" not in self.scopes:
            self.scopes = ["openid", *self.scopes]
        if (
            self.token_endpoint_auth_method in ("client_secret_basic", "client_secret_post")
            and not self.client_secret
        ):
            raise ValueError(
                f"token_endpoint_auth_method {self.token_endpoint_auth_method!r} "
                "requires 'client_secret'"
            )
        has_rule = any(
            (self.allowed_users, self.allowed_domains, self.allowed_groups, self.allowed_roles)
        )
        if not has_rule and not self.allow_all_users:
            raise ValueError(
                "OIDC provider needs at least one of allowed_users / allowed_domains / "
                "allowed_groups / allowed_roles, or an explicit 'allow_all_users: true'"
            )
        return self

    @property
    def is_multi_tenant(self) -> bool:
        return self.type == "entra" and (self.tenant_id or "").lower() in (
            ENTRA_MULTI_TENANT_ALIASES
        )

    @property
    def resolved_issuer(self) -> str:
        """The configured issuer (for Entra: derived from tenant + authority host)."""
        if self.type == "entra":
            return f"{self.authority_host}/{self.tenant_id}/v2.0"
        assert self.issuer is not None
        return self.issuer.rstrip("/")

    @property
    def resolved_discovery_url(self) -> str:
        if self.discovery_url:
            return self.discovery_url
        return f"{self.resolved_issuer}/.well-known/openid-configuration"

    @property
    def resolved_username_claim(self) -> str:
        if self.username_claim:
            return self.username_claim
        return "preferred_username" if self.type == "entra" else "email"

    @property
    def resolved_display_name(self) -> str | None:
        if self.display_name:
            return self.display_name
        return "Microsoft" if self.type == "entra" else None


class ServerConfig(BaseModel):
    # Public HTTPS URL clients use to reach the gateway (behind the reverse proxy).
    public_url: str
    host: str = "0.0.0.0"
    port: int = 8000
    # Peers uvicorn trusts to set X-Forwarded-For / X-Forwarded-Proto (a
    # reverse proxy's own address, or a comma-separated list of them).
    # Trusting these headers from arbitrary clients lets them spoof their
    # source IP (poisoning audit logs and rate limiting) and claim
    # X-Forwarded-Proto: https on a plaintext connection. Defaults to
    # loopback only, which covers `docker compose`'s common
    # reverse-proxy-on-the-host pattern; set explicitly (e.g. the Docker
    # bridge subnet, or "*" only if you fully trust the network path) when
    # the proxy connects from elsewhere.
    trusted_proxy_ips: str = "127.0.0.1"

    @field_validator("public_url")
    @classmethod
    def _normalize_public_url(cls, v: str) -> str:
        return v.rstrip("/")


class AuthConfig(BaseModel):
    # Local username/password accounts. May be empty when users sign in via `oidc` only.
    users: list[UserConfig] = Field(default_factory=list)
    # External OpenID Connect providers (standard OIDC or Microsoft Entra ID),
    # keyed by a short name used in the callback URL
    # <public_url>/auth/oidc/<name>/callback.
    oidc: dict[str, OIDCProviderConfig] = Field(default_factory=dict)
    # Fernet key (or arbitrary passphrase, which is stretched via scrypt) used to
    # encrypt secrets at rest in the SQLite database. Normally supplied via
    # ${MCP_GATEWAY_ENCRYPTION_KEY}; set MCP_GATEWAY_ENCRYPTION_KEY_FILE instead
    # to read it from a file (e.g. a Docker/Compose secret) -- see
    # _read_encryption_key_file() and the README's "Encryption key" section.
    encryption_key: str

    @field_validator("encryption_key")
    @classmethod
    def _check_encryption_key(cls, v: str) -> str:
        if not v:
            raise ValueError(
                "auth.encryption_key is empty -- set MCP_GATEWAY_ENCRYPTION_KEY or "
                "MCP_GATEWAY_ENCRYPTION_KEY_FILE"
            )
        return v

    # Secret for signing browser session cookies; derived from encryption_key when unset.
    session_secret: str | None = None
    access_token_expiry_seconds: int = 3600
    refresh_token_expiry_seconds: int = 60 * 60 * 24 * 30
    authorization_code_expiry_seconds: int = 300
    login_session_expiry_seconds: int = 60 * 60 * 8
    # Optional allow-list of redirect URI patterns for dynamically registered /
    # CIMD clients (e.g. "https://claude.ai/*"). When unset, standard validation
    # applies: exact match against registered URIs with loopback ports allowed to vary.
    allowed_client_redirect_uris: list[str] | None = None
    # Scopes advertised to MCP clients. The gateway is a single-identity AS, so
    # scopes are informational; "mcp" is the default catch-all.
    scopes_supported: list[str] = Field(default_factory=lambda: ["mcp"])

    @field_validator("oidc")
    @classmethod
    def _validate_oidc_names(
        cls, v: dict[str, OIDCProviderConfig]
    ) -> dict[str, OIDCProviderConfig]:
        for name in v:
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", name):
                raise ValueError(
                    f"OIDC provider name {name!r} must be alphanumeric with '-'/'_' "
                    "(it is part of the callback URL)"
                )
        return v


class BackendAuthConfig(BaseModel):
    """How the gateway authenticates against an upstream MCP server."""

    type: Literal["none", "bearer", "headers", "oauth"] = "none"
    # type == "bearer": static token injected as `Authorization: Bearer <token>`.
    token: str | None = None
    # type == "headers": arbitrary static headers (e.g. X-API-Key).
    headers: dict[str, str] = Field(default_factory=dict)
    # type == "oauth": scopes to request from the upstream authorization server.
    scopes: list[str] | None = None
    # type == "oauth": force DCR even if the upstream AS supports CIMD.
    prefer_dcr: bool = False
    # type == "oauth": pre-registered client credentials. Required for upstream
    # authorization servers that support neither CIMD nor Dynamic Client
    # Registration (e.g. GitHub's, which requires a manually created OAuth App).
    # When set, these are used directly and no CIMD/DCR is attempted.
    client_id: str | None = None
    client_secret: str | None = None

    @model_validator(mode="after")
    def _check(self) -> BackendAuthConfig:
        if self.type == "bearer" and not self.token:
            raise ValueError("backend auth type 'bearer' requires 'token'")
        if self.type == "headers" and not self.headers:
            raise ValueError("backend auth type 'headers' requires 'headers'")
        if self.type != "oauth" and self.client_secret:
            raise ValueError("client_secret is only valid for auth type 'oauth'")
        return self


class BackendConfig(BaseModel):
    """An upstream MCP server exposed through the gateway."""

    url: str
    enabled: bool = True
    auth: BackendAuthConfig = Field(default_factory=BackendAuthConfig)
    # Extra static headers sent with every request regardless of auth type.
    headers: dict[str, str] = Field(default_factory=dict)


class StorageConfig(BaseModel):
    path: str = "data/gateway.db"


class GatewayConfig(BaseModel):
    server: ServerConfig
    auth: AuthConfig
    storage: StorageConfig = Field(default_factory=StorageConfig)
    backends: dict[str, BackendConfig] = Field(default_factory=dict)

    @field_validator("backends")
    @classmethod
    def _validate_backend_names(cls, v: dict[str, BackendConfig]) -> dict[str, BackendConfig]:
        for name in v:
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", name):
                raise ValueError(
                    f"Backend name {name!r} must be alphanumeric with '-'/'_' "
                    "(it is used as a tool-name prefix)"
                )
        return v


def _read_encryption_key_file() -> str | None:
    """Read the key from MCP_GATEWAY_ENCRYPTION_KEY_FILE, if set. Returns
    None if the variable isn't set.

    Deliberately does *not* go through os.environ (e.g. by setting
    MCP_GATEWAY_ENCRYPTION_KEY and letting the normal ${...} expansion pick it
    up): an environment variable is readable by anything sharing this
    process's UID via /proc/<pid>/environ, gets swept up by crash-reporting/APM
    tools' default "environment" capture, and is inherited by every child
    process -- exactly the leak surface a file-based secret (Docker/Compose
    `secrets:`, a Kubernetes `Secret` volume, a Vault Agent sidecar -- see
    https://docs.docker.com/compose/how-tos/use-secrets/) is meant to avoid.
    The value returned here is spliced directly into the parsed config dict
    by load_config() instead, entirely in this process's own memory.
    """
    key_file = os.environ.get("MCP_GATEWAY_ENCRYPTION_KEY_FILE")
    if not key_file:
        return None
    try:
        return Path(key_file).read_text().strip()
    except OSError as exc:
        raise ValueError(
            f"MCP_GATEWAY_ENCRYPTION_KEY_FILE={key_file!r} could not be read: {exc}"
        ) from exc


def load_config(path: str | Path) -> GatewayConfig:
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise TypeError(f"Config file {path} must contain a YAML mapping")
    expanded = _expand_tree(raw)

    key_from_file = _read_encryption_key_file()
    if key_from_file is not None:
        auth = expanded.setdefault("auth", {}) if isinstance(expanded, dict) else {}
        if isinstance(auth, dict):
            auth["encryption_key"] = key_from_file

    return GatewayConfig.model_validate(expanded)


def load_storage_path(path: str | Path) -> str:
    """Read just `storage.path` from a config file, without requiring the
    rest of the config -- notably `auth.encryption_key` -- to validate.

    Used by `mcp-gateway rotate-key`, which supplies its own keys via
    --old-key-file/--new-key-file and so doesn't need a working
    encryption_key just to locate the database.
    """
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise TypeError(f"Config file {path} must contain a YAML mapping")
    storage_raw = _expand_tree(raw.get("storage") or {})
    return str(storage_raw.get("path", StorageConfig().path))
