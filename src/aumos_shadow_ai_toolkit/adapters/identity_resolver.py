"""SSO / CASB identity resolution adapter.

Resolves internal IP addresses to user identities via Okta or Azure AD.
Used to enrich proxy event records with user context for targeted intervention.

GAP-249: SSO / CASB Integration
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class UserIdentity:
    """Resolved user identity from SSO provider.

    Attributes:
        user_id: IdP-assigned user UUID string.
        email: User email address.
        department: Organisational department.
        display_name: User display name.
        ip_address: The source IP that was resolved.
    """

    def __init__(
        self,
        user_id: str,
        email: str,
        department: str | None,
        display_name: str | None,
        ip_address: str,
    ) -> None:
        self.user_id = user_id
        self.email = email
        self.department = department
        self.display_name = display_name
        self.ip_address = ip_address


class OktaIdentityResolverAdapter:
    """Resolves IP addresses to user identities via Okta System Log API.

    Queries the Okta System Log for recent authentication events matching
    a given internal IP address within a ±1 hour window of the event.

    PRIVACY INVARIANT: Only authentication metadata is queried — no user
    content, browsing history, or personal data beyond organisational context
    (email, department, display name) is retrieved.

    Args:
        okta_base_url: Okta tenant URL (e.g. https://company.okta.com).
        okta_api_token: Okta API token with okta.logs.read scope.
        http_client: Async HTTP client for Okta API calls.
    """

    def __init__(
        self,
        okta_base_url: str,
        okta_api_token: str,
        http_client: httpx.AsyncClient,
    ) -> None:
        """Initialise with Okta credentials and HTTP client.

        Args:
            okta_base_url: Okta tenant base URL.
            okta_api_token: SSWS token with okta.logs.read scope.
            http_client: Async HTTP client.
        """
        self._okta_base_url = okta_base_url.rstrip("/")
        self._okta_api_token = okta_api_token
        self._http_client = http_client

    async def resolve_ip_to_user(
        self,
        ip_address: str,
        timestamp: datetime,
    ) -> UserIdentity | None:
        """Query Okta System Log for recent authentication events from this IP.

        Searches a ±1 hour window around the event timestamp for any
        successful authentication event originating from the given IP.
        Returns the most recent match.

        Args:
            ip_address: Internal IP address to resolve.
            timestamp: Event timestamp to anchor the search window.

        Returns:
            UserIdentity if resolved, None if identity cannot be determined.
        """
        since = (timestamp - timedelta(hours=1)).astimezone(timezone.utc)
        until = (timestamp + timedelta(minutes=5)).astimezone(timezone.utc)

        try:
            response = await self._http_client.get(
                f"{self._okta_base_url}/api/v1/logs",
                params={
                    "filter": f'client.ipAddress eq "{ip_address}" and outcome.result eq "SUCCESS"',
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                    "limit": 1,
                },
                headers={
                    "Authorization": f"SSWS {self._okta_api_token}",
                    "Accept": "application/json",
                },
                timeout=10.0,
            )

            if response.status_code != 200:
                logger.warning(
                    "Okta API returned non-200",
                    status_code=response.status_code,
                    ip_address=ip_address,
                )
                return None

            events: list[dict[str, Any]] = response.json()
            if not events:
                return None

            event = events[0]
            actor = event.get("actor", {})
            user_id = actor.get("id", "")
            email = actor.get("login", "")
            display_name = actor.get("displayName")

            # Department requires a separate SCIM profile lookup in production;
            # omitted here to keep the adapter focused on the log query.
            return UserIdentity(
                user_id=user_id,
                email=email,
                department=None,
                display_name=display_name,
                ip_address=ip_address,
            )

        except httpx.TimeoutException:
            logger.warning("Okta identity resolution timed out", ip_address=ip_address)
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Okta identity resolution failed",
                ip_address=ip_address,
                error=str(exc),
            )
            return None


class AzureADIdentityResolverAdapter:
    """Resolves IP addresses to user identities via Azure AD Sign-In Logs.

    Queries Microsoft Graph API sign-in logs to find the user most recently
    authenticated from a given internal IP address.

    Args:
        tenant_id: Azure AD tenant UUID.
        client_id: Azure AD app registration client ID.
        client_secret: Azure AD app registration client secret.
        http_client: Async HTTP client.
    """

    _GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
    _TOKEN_ENDPOINT_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        http_client: httpx.AsyncClient,
    ) -> None:
        """Initialise with Azure AD credentials.

        Args:
            tenant_id: Azure AD tenant UUID.
            client_id: App registration client ID.
            client_secret: App registration client secret.
            http_client: Async HTTP client.
        """
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._http_client = http_client
        self._access_token: str | None = None
        self._token_expiry: datetime | None = None

    async def _get_access_token(self) -> str:
        """Acquire or refresh the Microsoft Graph API access token.

        Returns:
            Valid access token string.

        Raises:
            RuntimeError: If token acquisition fails.
        """
        now = datetime.now(tz=timezone.utc)
        if self._access_token and self._token_expiry and self._token_expiry > now:
            return self._access_token

        token_url = self._TOKEN_ENDPOINT_TEMPLATE.format(tenant_id=self._tenant_id)
        response = await self._http_client.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=10.0,
        )

        if response.status_code != 200:
            raise RuntimeError(f"Azure AD token acquisition failed: {response.status_code}")

        token_data = response.json()
        self._access_token = token_data["access_token"]
        self._token_expiry = now + timedelta(seconds=token_data.get("expires_in", 3600) - 60)
        return self._access_token

    async def resolve_ip_to_user(
        self,
        ip_address: str,
        timestamp: datetime,
    ) -> UserIdentity | None:
        """Query Azure AD sign-in logs for recent events from this IP.

        Args:
            ip_address: Internal IP address to resolve.
            timestamp: Event timestamp to anchor the search window.

        Returns:
            UserIdentity if resolved, None otherwise.
        """
        try:
            token = await self._get_access_token()
            since = (timestamp - timedelta(hours=1)).astimezone(timezone.utc)

            response = await self._http_client.get(
                f"{self._GRAPH_BASE_URL}/auditLogs/signIns",
                params={
                    "$filter": (
                        f"ipAddress eq '{ip_address}' and "
                        f"status/errorCode eq 0 and "
                        f"createdDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                    ),
                    "$top": "1",
                    "$orderby": "createdDateTime desc",
                    "$select": "userId,userPrincipalName,userDisplayName,ipAddress",
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=10.0,
            )

            if response.status_code != 200:
                return None

            data = response.json()
            sign_ins: list[dict[str, Any]] = data.get("value", [])
            if not sign_ins:
                return None

            sign_in = sign_ins[0]
            return UserIdentity(
                user_id=sign_in.get("userId", ""),
                email=sign_in.get("userPrincipalName", ""),
                department=None,
                display_name=sign_in.get("userDisplayName"),
                ip_address=ip_address,
            )

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Azure AD identity resolution failed",
                ip_address=ip_address,
                error=str(exc),
            )
            return None
