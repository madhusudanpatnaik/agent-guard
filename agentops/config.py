"""Central configuration for the AgentOps control plane.

Settings are read from environment variables (or a local ``.env`` file) so the
same image runs unchanged from a laptop to a Fortune 500 cluster.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Checked-in dev default. The production guard (Settings.production_problems)
# refuses to boot if this value survives into a production environment.
DEV_SECRET_DEFAULT = "dev-insecure-change-me-please-0000000000000000"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Core -----------------------------------------------------------
    app_name: str = "AgentOps Control Plane"
    environment: str = "development"
    database_url: str = "sqlite:///./agentops.db"

    # --- Security -------------------------------------------------------
    # In production this MUST be overridden with a long random value.
    secret_key: str = DEV_SECRET_DEFAULT
    # Dedicated key for encrypting connector secrets. Kept separate from
    # secret_key so credentials can be rotated WITHOUT re-keying (and thereby
    # invalidating) the append-only audit ledger. Falls back to secret_key.
    vault_key: str = ""
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 60 * 60 * 8  # 8h console sessions

    # Bootstrap admin created on first launch if no users exist.
    bootstrap_admin_email: str = "admin@agentops.local"
    bootstrap_admin_password: str = "admin"

    # --- Enterprise SSO (OpenID Connect) -------------------------------
    # Set oidc_issuer + oidc_client_id to enable "Sign in with your IdP".
    oidc_issuer: str = ""          # e.g. https://login.microsoftonline.com/<tenant>/v2.0
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""    # e.g. https://agentops.corp/api/auth/oidc/callback
    oidc_default_role: str = "viewer"   # least privilege for auto-provisioned users
    oidc_allowed_domain: str = ""       # optional: restrict to one email domain

    # --- Governance defaults -------------------------------------------
    # When an agent's role has no matching allow policy, the platform denies
    # by default (zero-trust). Set to False only for permissive dev sandboxes.
    default_deny: bool = True

    # Block outbound actions whose payload contains detected secrets/PII when
    # the resource is classified as an external egress target.
    dlp_block_egress_on_secret: bool = True

    # SSRF guard: refuse connector HTTP calls to private / loopback / link-local /
    # cloud-metadata addresses. None = follow environment (off in dev so the local
    # demo works, on in production). Set explicitly to force on/off.
    block_private_egress: bool | None = None

    # Per-agent request budget over the rolling window (see quota_window_seconds).
    default_agent_quota: int = 10_000
    quota_window_seconds: int = 60 * 60  # 1h

    # Pending approvals older than this are treated as expired (fail-closed).
    approval_ttl_seconds: int = 60 * 60  # 1h

    # Upper bound on the request payload we will DLP-scan; larger payloads are
    # scanned truncated and flagged, so a huge body can't exhaust CPU/threads.
    max_request_scan_bytes: int = 256 * 1024  # 256 KiB

    # Global HTTP request body ceiling (bytes). Bodies larger than this are
    # rejected with 413 before being read into memory — prevents OOM / DoS.
    max_request_body_bytes: int = 1_048_576  # 1 MiB

    # Login brute-force protection: max failures per source IP per window.
    login_rate_limit_count: int = 5
    login_rate_limit_window: int = 300  # seconds (5 minutes)

    # Content-Security-Policy header (empty = sensible default for the console).
    csp_policy: str = ""

    # --- Observability / integrity -------------------------------------
    # Append-only anchor of the ledger head, written OUTSIDE the primary DB so a
    # DB-only attacker cannot truncate the ledger head undetected. Empty disables.
    audit_anchor_path: str = "./agentops-ledger-anchor.log"
    # Optional SIEM sink: every decision is POSTed here as JSON (best-effort).
    siem_webhook_url: str = ""
    # If set, every outbound webhook (alerts + SIEM) is signed with
    # HMAC-SHA256 over the exact request body in an ``X-AgentOps-Signature:
    # sha256=<hex>`` header, so receivers can verify authenticity + integrity.
    webhook_signing_secret: str = ""

    # --- Detect & respond (alerting) -----------------------------------
    # High-risk events (DLP blocks, denial spikes) raise alerts; if set, each new
    # alert is POSTed here (Slack-formatted for hooks.slack.com URLs, else JSON).
    alert_webhook_url: str = ""
    # A burst of >= N denials from one agent within the window raises an anomaly.
    alert_denial_spike_count: int = 5
    alert_denial_spike_window: int = 60  # seconds
    # Minimum severity that triggers the webhook (info|low|medium|high|critical).
    alert_webhook_min_severity: str = "medium"
    # Webhook dedup: at most one notification per (org, kind, agent) in this many
    # seconds, so an incident that raises the same alert repeatedly doesn't flood
    # the channel. The alert is always recorded in the DB regardless. 0 disables.
    alert_webhook_dedup_window: int = 60
    # Automated containment: after N exfiltration attempts (within the spike window)
    # the offending agent is automatically SUSPENDED. 0 disables auto-containment.
    auto_suspend_on_exfil_attempts: int = 0

    # Human-in-the-loop: when an action needs approval, POST the pending request
    # here so operators are told a decision is waiting (Slack-formatted for
    # hooks.slack.com URLs, else generic JSON). Empty falls back to the alert
    # webhook; if both are empty, no approval notification is sent.
    approval_webhook_url: str = ""

    # --- Adaptive risk scoring -----------------------------------------
    # Compute a 0–100 risk score per decision (behavioral baselines + DLP +
    # egress + amount + novelty). Informational unless a threshold below is set.
    risk_scoring_enabled: bool = True
    # At/above this score, an ALLOW is escalated to REQUIRE_APPROVAL (adaptive
    # dual control). 0 disables step-up (decisions are never changed by risk).
    risk_step_up_threshold: int = 0
    # At/above this score, a high_risk alert is raised. 0 disables risk alerts.
    risk_alert_threshold: int = 0

    # --- Risk hot-path budget (latency vs. detection fidelity) ----------
    # Behavioral signals are derived from ONE bounded window fetch. This caps how
    # many recent rows that fetch may pull, bounding per-request work regardless
    # of how busy an agent is.
    risk_profile_max_rows: int = 500
    # When the window says a resource/action is new, additionally run an exact
    # unbounded-history lookup (up to 2 extra queries) before calling it novel.
    # True  = fewer false "novel" flags on long-lived agents (higher fidelity).
    # False = strictly bounded query count (lowest latency).
    risk_exact_novelty: bool = True
    # Repeats of the same (action, resource) back-to-back that indicate an agent
    # stuck in a tool-calling loop. 0 disables the signal.
    risk_loop_repeat_threshold: int = 10

    # --- Database connection pool --------------------------------------
    # Sized against the ASGI threadpool: sync endpoints each hold a connection
    # for the request, so a pool smaller than the worker count causes queueing
    # that looks like latency. 0 = SQLAlchemy default.
    db_pool_size: int = 20
    db_max_overflow: int = 20
    db_pool_timeout: int = 30
    db_pool_recycle: int = 1800  # recycle connections every 30m (stale-conn guard)
    # Pool for *connector* databases (the upstreams agents query through the
    # plane). Engines are cached per DSN, so these bound each upstream's pool.
    connector_pool_size: int = 5
    connector_max_overflow: int = 10

    # --- Server ---------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8080
    cors_origins: list[str] = ["*"]

    # --- Upstream resilience (enforced execution + proxy) --------------
    # Bounded retries with linear backoff on connection errors / timeouts / 5xx.
    upstream_max_retries: int = 2
    upstream_retry_backoff: float = 0.2  # seconds, multiplied by attempt number
    # Per-connector/host circuit breaker: open after N consecutive failed calls,
    # fast-fail for the cooldown, then allow one trial call to close it again.
    circuit_fail_threshold: int = 5
    circuit_cooldown_seconds: float = 30.0

    # --- Transparent proxy ---------------------------------------------
    # Where the proxy's TLS-interception CA (and per-host leaf certs) live.
    proxy_ca_dir: str = "./agentops-ca"
    # Verify the real origin's certificate when the proxy re-encrypts to it.
    # Only disable for local testing against self-signed origins.
    proxy_verify_upstream_tls: bool = True

    # --- Scale: rate/quota counter backend -----------------------------
    # "db"    — COUNT(*) over the audit ledger (default, zero-infra, correct).
    # "redis" — Redis sorted-set sliding window for sub-ms evaluation shared
    #           across horizontally scaled gateway nodes (needs redis_url).
    rate_limit_backend: str = "db"
    redis_url: str = ""  # e.g. redis://localhost:6379/0

    # --- Guardrails: pluggable DLP + LLM-security -----------------------
    # Extra DLP providers layered on top of the built-in regex scanner.
    # "presidio" enables ML-based PII entity recognition (needs presidio-analyzer).
    dlp_providers: list[str] = []
    # Detect prompt-injection / jailbreak attempts in agent-bound text.
    llm_guard_enabled: bool = True
    # Optional LLM-native moderation webhook (POST text -> {"flagged": bool,...}).
    llm_guard_webhook_url: str = ""

    # --- Policy-as-code: external evaluator ----------------------------
    # "" (built-in engine), "opa" (Open Policy Agent HTTP data API), or
    # "cedar" (a Cedar authorization sidecar exposing /authorize).
    policy_engine: str = ""
    policy_engine_url: str = ""   # e.g. http://localhost:8181/v1/data/agentops/allow
    policy_engine_fail_open: bool = False  # fail-closed by default

    # --- Distributed audit anchoring -----------------------------------
    # Anchor the ledger head to tamper-evident external stores in addition to
    # the local file. Any of: "file" (default), "transparency_log", "rfc3161".
    audit_anchor_backends: list[str] = ["file"]
    # Transparency-log sink (Rekor-style): POST {seq,hash,...} -> {"uuid"|"logIndex"}.
    transparency_log_url: str = ""
    # RFC-3161 Time-Stamp Authority URL (returns a signed timestamp token).
    rfc3161_tsa_url: str = ""

    # --- Observability: OpenTelemetry ----------------------------------
    # Emit OTel spans across authorize/execute/proxy (no-op unless the
    # opentelemetry packages are installed AND this is enabled).
    otel_enabled: bool = False
    otel_service_name: str = "agentops"
    # OTLP exporter endpoint; empty uses the SDK default / env (OTEL_EXPORTER_*).
    otel_exporter_otlp_endpoint: str = ""

    # --- Enterprise identity: SCIM 2.0 ---------------------------------
    # Bearer token an IdP (Okta/Azure AD) presents to the SCIM provisioning
    # endpoints. Empty disables SCIM.
    scim_bearer_token: str = ""

    # --- Logging --------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True  # JSON-lines logs for the agentops.* namespace

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    def effective_vault_key(self) -> str:
        return self.vault_key or self.secret_key

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id)

    def egress_guard_enabled(self) -> bool:
        return self.is_production if self.block_private_egress is None else self.block_private_egress

    def production_problems(self) -> list[str]:
        """Fail-closed configuration checks enforced at startup in production.

        A control plane that governs other software must never boot with
        checked-in default credentials or signing keys.
        """
        if not self.is_production:
            return []
        problems: list[str] = []
        weak_secrets = {DEV_SECRET_DEFAULT, "please-change-this-in-prod", ""}
        if self.secret_key in weak_secrets or len(self.secret_key) < 32:
            problems.append(
                "AGENTOPS_SECRET_KEY must be a strong random value (>=32 chars) in production"
            )
        if self.bootstrap_admin_password in {"admin", ""}:
            problems.append(
                "AGENTOPS_BOOTSTRAP_ADMIN_PASSWORD must be changed from the default in production"
            )
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
