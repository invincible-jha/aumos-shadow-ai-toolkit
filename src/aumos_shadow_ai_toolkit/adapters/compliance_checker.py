"""Compliance checking adapter for shadow AI regulatory risk assessment.

Implements ShadowComplianceChecker which evaluates unauthorized AI tool usage
against GDPR, HIPAA, SOX, PCI-DSS, and other regulatory frameworks to identify
violations, quantify severity, and produce remediation recommendations.

All checks are purely metadata-based — no user data content is read or stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Compliance framework definitions
# ---------------------------------------------------------------------------

# Map: framework → applicable data categories.
_FRAMEWORK_DATA_TRIGGERS: dict[str, frozenset[str]] = {
    "GDPR": frozenset({"pii", "healthcare", "financial", "internal"}),
    "HIPAA": frozenset({"healthcare", "pii"}),
    "PCI_DSS": frozenset({"financial", "pii"}),
    "SOX": frozenset({"financial", "ip"}),
    "CCPA": frozenset({"pii", "financial"}),
    "SOC2": frozenset({"internal", "ip", "confidential"}),
    "ISO_27001": frozenset({"confidential", "internal", "ip"}),
    "NIST": frozenset({"internal", "ip", "confidential"}),
}

# Violation severity weights (1.0 = maximum severity).
_FRAMEWORK_SEVERITY: dict[str, float] = {
    "GDPR": 0.9,
    "HIPAA": 1.0,
    "PCI_DSS": 0.95,
    "SOX": 0.85,
    "CCPA": 0.7,
    "SOC2": 0.6,
    "ISO_27001": 0.55,
    "NIST": 0.5,
}

# Maximum potential fine per regulatory framework (USD).
_FRAMEWORK_MAX_FINE_USD: dict[str, int] = {
    "GDPR": 20_000_000,
    "HIPAA": 1_900_000,
    "PCI_DSS": 500_000,
    "SOX": 5_000_000,
    "CCPA": 7_500,
    "SOC2": 0,
    "ISO_27001": 0,
    "NIST": 0,
}

# Data residency violation: endpoints hosted outside EU/EEA trigger GDPR residency flags.
_EU_RESIDENCY_REQUIRED_FRAMEWORKS: frozenset[str] = frozenset({"GDPR"})

# Third-party AI endpoints that process data outside the enterprise perimeter.
_THIRD_PARTY_ENDPOINTS: frozenset[str] = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "api.perplexity.ai",
        "generativelanguage.googleapis.com",
        "api.cohere.com",
        "api.mistral.ai",
        "api.together.xyz",
        "api.replicate.com",
        "api.huggingface.co",
        "api.groq.com",
    }
)

# Severity classification thresholds (0.0–1.0 violation severity score).
_SEV_CRITICAL: float = 0.75
_SEV_HIGH: float = 0.55
_SEV_MEDIUM: float = 0.35


class ShadowComplianceChecker:
    """Regulatory compliance checker for shadow AI tool usage.

    Evaluates discovered shadow AI activity against configurable compliance
    frameworks to identify violations, classify severity, and produce
    actionable remediation recommendations.

    The checker operates on metadata only — it never reads or stores
    request/response content from shadow AI tool traffic.
    """

    def __init__(
        self,
        active_frameworks: list[str] | None = None,
        eu_data_residency_required: bool = False,
        pii_classification_strict: bool = True,
    ) -> None:
        """Initialise the compliance checker.

        Args:
            active_frameworks: List of compliance frameworks in scope for this
                tenant. Defaults to all frameworks if not specified.
            eu_data_residency_required: If True, all third-party endpoints
                trigger a GDPR data residency violation flag.
            pii_classification_strict: If True, ambiguous data categories are
                treated as PII for GDPR/HIPAA evaluation purposes.
        """
        self._active_frameworks = frozenset(
            active_frameworks or list(_FRAMEWORK_SEVERITY.keys())
        )
        self._eu_residency = eu_data_residency_required
        self._strict_pii = pii_classification_strict

    async def assess_discovery(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        data_sensitivity: str,
        request_count: int,
        estimated_volume_kb: int,
        detection_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assess a single shadow AI discovery for compliance violations.

        Evaluates the discovery against all active frameworks and returns
        the applicable violations with severity scores and remediation steps.

        Args:
            tenant_id: Tenant UUID (audit context).
            tool_name: Human-readable tool name.
            api_endpoint: Detected API endpoint domain.
            data_sensitivity: Data sensitivity category from risk scorer.
            request_count: Total detected API calls.
            estimated_volume_kb: Estimated data volume in kilobytes.
            detection_metadata: Optional additional scanner metadata.

        Returns:
            Compliance assessment dict with violations, severity, and remediation.
        """
        effective_sensitivity = (
            "pii"
            if self._strict_pii and data_sensitivity in ("unknown", "internal")
            else data_sensitivity
        )

        violations = self._identify_violations(
            api_endpoint=api_endpoint,
            data_sensitivity=effective_sensitivity,
            request_count=request_count,
            estimated_volume_kb=estimated_volume_kb,
        )

        pii_risk = self._assess_pii_exposure(data_sensitivity, request_count, api_endpoint)
        residency_violations = self._check_data_residency(api_endpoint, effective_sensitivity)

        overall_severity_score = self._compute_overall_severity(violations)
        severity_label = self._classify_severity(overall_severity_score)

        total_fine_exposure = sum(v.get("potential_fine_exposure_usd", 0) for v in violations)

        remediation_steps = self._generate_remediation(violations, tool_name, api_endpoint)

        logger.info(
            "Compliance assessment complete",
            tenant_id=str(tenant_id),
            tool_name=tool_name,
            violation_count=len(violations),
            severity=severity_label,
            fine_exposure_usd=total_fine_exposure,
        )

        return {
            "tool_name": tool_name,
            "api_endpoint": api_endpoint,
            "data_sensitivity": effective_sensitivity,
            "violation_count": len(violations),
            "violations": violations,
            "data_residency_violations": residency_violations,
            "pii_exposure_risk": pii_risk,
            "overall_severity_score": round(overall_severity_score, 4),
            "severity_label": severity_label,
            "total_fine_exposure_usd": total_fine_exposure,
            "remediation_steps": remediation_steps,
            "assessed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def assess_portfolio(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assess compliance violations across an entire shadow AI portfolio.

        Aggregates per-discovery assessments into a portfolio-level compliance
        report grouped by framework and severity.

        Args:
            tenant_id: Tenant UUID.
            discoveries: List of discovery dicts with tool_name, api_endpoint,
                data_sensitivity, request_count, and estimated_data_volume_kb.

        Returns:
            Portfolio compliance report dict.
        """
        assessments: list[dict[str, Any]] = []
        for discovery in discoveries:
            assessment = await self.assess_discovery(
                tenant_id=tenant_id,
                tool_name=discovery.get("tool_name", "unknown"),
                api_endpoint=discovery.get("api_endpoint", ""),
                data_sensitivity=discovery.get("data_sensitivity", "unknown"),
                request_count=discovery.get("request_count", 0),
                estimated_volume_kb=discovery.get("estimated_data_volume_kb", 0),
                detection_metadata=discovery.get("risk_details"),
            )
            assessments.append(assessment)

        by_framework: dict[str, list[str]] = {}
        total_fine_exposure = 0
        severity_distribution: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0
        }

        for assessment in assessments:
            severity_distribution[assessment.get("severity_label", "low")] = (
                severity_distribution.get(assessment.get("severity_label", "low"), 0) + 1
            )
            total_fine_exposure += assessment.get("total_fine_exposure_usd", 0)
            for violation in assessment.get("violations", []):
                framework = violation.get("framework", "unknown")
                by_framework.setdefault(framework, [])
                if assessment["tool_name"] not in by_framework[framework]:
                    by_framework[framework].append(assessment["tool_name"])

        logger.info(
            "Portfolio compliance assessment complete",
            tenant_id=str(tenant_id),
            discovery_count=len(discoveries),
            critical_count=severity_distribution["critical"],
            total_fine_exposure_usd=total_fine_exposure,
        )

        return {
            "total_discoveries_assessed": len(assessments),
            "severity_distribution": severity_distribution,
            "frameworks_violated": list(by_framework.keys()),
            "tools_per_violated_framework": by_framework,
            "total_fine_exposure_usd": total_fine_exposure,
            "assessments": assessments,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def check_framework_mapping(
        self,
        tenant_id: uuid.UUID,
        data_sensitivity: str,
        api_endpoint: str,
    ) -> dict[str, list[str]]:
        """Map a discovery to applicable compliance frameworks.

        Returns which frameworks are triggered by the given data sensitivity
        category and whether the API endpoint is an external third party.

        Args:
            tenant_id: Tenant UUID.
            data_sensitivity: Data sensitivity category.
            api_endpoint: API endpoint domain.

        Returns:
            Dict mapping framework name to list of triggered violation reasons.
        """
        mapping: dict[str, list[str]] = {}
        for framework in self._active_frameworks:
            triggers = _FRAMEWORK_DATA_TRIGGERS.get(framework, frozenset())
            reasons: list[str] = []
            if data_sensitivity in triggers:
                reasons.append(f"{data_sensitivity.upper()} data category triggers {framework}")
            if api_endpoint in _THIRD_PARTY_ENDPOINTS:
                reasons.append(f"Third-party data processor {api_endpoint} is not DPA-covered")
            if self._eu_residency and framework in _EU_RESIDENCY_REQUIRED_FRAMEWORKS:
                reasons.append(f"Data residency requirement violated: endpoint not EU-hosted")
            if reasons:
                mapping[framework] = reasons
        return mapping

    async def generate_compliance_report(
        self,
        tenant_id: uuid.UUID,
        portfolio_assessment: dict[str, Any],
    ) -> dict[str, Any]:
        """Format a portfolio assessment into a structured compliance report.

        Args:
            tenant_id: Tenant UUID.
            portfolio_assessment: Output of assess_portfolio().

        Returns:
            Formatted compliance report dict.
        """
        critical_items = [
            a for a in portfolio_assessment.get("assessments", [])
            if a.get("severity_label") == "critical"
        ]
        high_items = [
            a for a in portfolio_assessment.get("assessments", [])
            if a.get("severity_label") == "high"
        ]

        executive_summary = (
            f"Compliance review identified "
            f"{portfolio_assessment['total_discoveries_assessed']} shadow AI instances "
            f"with {len(portfolio_assessment.get('frameworks_violated', []))} regulatory "
            f"frameworks at risk. Estimated fine exposure: "
            f"USD {portfolio_assessment.get('total_fine_exposure_usd', 0):,}. "
            f"Immediate remediation required for {len(critical_items)} critical "
            f"and {len(high_items)} high-severity items."
        )

        return {
            "report_type": "compliance_report",
            "tenant_id": str(tenant_id),
            "executive_summary": executive_summary,
            "severity_distribution": portfolio_assessment.get("severity_distribution", {}),
            "frameworks_violated": portfolio_assessment.get("frameworks_violated", []),
            "total_fine_exposure_usd": portfolio_assessment.get("total_fine_exposure_usd", 0),
            "critical_items": [
                {
                    "tool_name": a["tool_name"],
                    "violations": [v["framework"] for v in a.get("violations", [])],
                    "fine_exposure_usd": a.get("total_fine_exposure_usd", 0),
                    "priority_remediation": a.get("remediation_steps", [])[:2],
                }
                for a in critical_items
            ],
            "high_items": [
                {
                    "tool_name": a["tool_name"],
                    "violations": [v["framework"] for v in a.get("violations", [])],
                }
                for a in high_items
            ],
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _identify_violations(
        self,
        api_endpoint: str,
        data_sensitivity: str,
        request_count: int,
        estimated_volume_kb: int,
    ) -> list[dict[str, Any]]:
        """Identify concrete regulatory violations for a single discovery.

        Args:
            api_endpoint: Detected API endpoint domain.
            data_sensitivity: Data sensitivity category.
            request_count: Number of detected API calls.
            estimated_volume_kb: Estimated data volume.

        Returns:
            List of violation dicts.
        """
        violations: list[dict[str, Any]] = []
        is_third_party = api_endpoint in _THIRD_PARTY_ENDPOINTS

        for framework in self._active_frameworks:
            triggers = _FRAMEWORK_DATA_TRIGGERS.get(framework, frozenset())
            if data_sensitivity not in triggers and not is_third_party:
                continue

            severity_score = _FRAMEWORK_SEVERITY.get(framework, 0.4)
            max_fine = _FRAMEWORK_MAX_FINE_USD.get(framework, 0)

            # Adjust fine exposure by severity and volume.
            volume_factor = min(1.0, estimated_volume_kb / 10_240)  # Cap at 10 MB scale.
            fine_exposure = int(max_fine * severity_score * 0.001 * (1 + volume_factor))

            violation_reason = self._build_violation_reason(
                framework, data_sensitivity, api_endpoint, is_third_party
            )

            violations.append(
                {
                    "framework": framework,
                    "violation_type": self._classify_violation_type(
                        framework, data_sensitivity, is_third_party
                    ),
                    "severity_score": round(severity_score, 4),
                    "violation_reason": violation_reason,
                    "request_count": request_count,
                    "estimated_volume_kb": estimated_volume_kb,
                    "potential_fine_exposure_usd": fine_exposure,
                }
            )

        return violations

    def _assess_pii_exposure(
        self, data_sensitivity: str, request_count: int, api_endpoint: str
    ) -> dict[str, Any]:
        """Score PII exposure risk for a discovery.

        Args:
            data_sensitivity: Data sensitivity category.
            request_count: Request count.
            api_endpoint: API endpoint domain.

        Returns:
            PII exposure risk dict.
        """
        is_pii_category = data_sensitivity in ("pii", "healthcare")
        is_third_party = api_endpoint in _THIRD_PARTY_ENDPOINTS

        exposure_score = 0.0
        if is_pii_category and is_third_party:
            exposure_score = min(1.0, 0.7 + min(0.3, request_count / 10_000))
        elif is_pii_category:
            exposure_score = 0.4
        elif is_third_party:
            exposure_score = 0.3
        else:
            exposure_score = 0.1

        return {
            "exposure_score": round(exposure_score, 4),
            "is_pii_sensitive": is_pii_category,
            "is_third_party_processor": is_third_party,
            "risk_label": self._classify_severity(exposure_score),
            "applicable_frameworks": [
                f for f in ("GDPR", "HIPAA", "CCPA")
                if f in self._active_frameworks and is_pii_category
            ],
        }

    def _check_data_residency(
        self, api_endpoint: str, data_sensitivity: str
    ) -> list[dict[str, Any]]:
        """Check for data residency violations.

        Args:
            api_endpoint: Detected API endpoint domain.
            data_sensitivity: Data sensitivity category.

        Returns:
            List of residency violation dicts. Empty if no violations found.
        """
        violations: list[dict[str, Any]] = []
        if not self._eu_residency:
            return violations

        triggers = _FRAMEWORK_DATA_TRIGGERS.get("GDPR", frozenset())
        if data_sensitivity not in triggers:
            return violations

        if api_endpoint in _THIRD_PARTY_ENDPOINTS:
            violations.append(
                {
                    "framework": "GDPR",
                    "violation_type": "data_residency",
                    "endpoint": api_endpoint,
                    "description": (
                        f"Data transferred to {api_endpoint} which may process data outside "
                        f"the EU/EEA, violating GDPR Article 46 cross-border transfer requirements."
                    ),
                    "remediation": (
                        "Verify the provider has EU Standard Contractual Clauses in place, "
                        "or migrate to an EU-hosted governed alternative."
                    ),
                }
            )
        return violations

    def _compute_overall_severity(
        self, violations: list[dict[str, Any]]
    ) -> float:
        """Compute an overall severity score from individual violations.

        Uses the maximum violation score combined with a diminishing-returns
        multi-violation penalty.

        Args:
            violations: List of violation dicts.

        Returns:
            Aggregate severity score in range [0.0, 1.0].
        """
        if not violations:
            return 0.0
        scores = [v.get("severity_score", 0.0) for v in violations]
        max_score = max(scores)
        multi_penalty = sum(
            (1.0 - max_score) * 0.04 * (idx + 1)
            for idx, _ in enumerate(scores[1:])
        )
        return min(1.0, max_score + multi_penalty)

    def _classify_severity(self, score: float) -> str:
        """Classify a 0.0–1.0 severity score into a label.

        Args:
            score: Severity score.

        Returns:
            Severity label: critical | high | medium | low.
        """
        if score >= _SEV_CRITICAL:
            return "critical"
        if score >= _SEV_HIGH:
            return "high"
        if score >= _SEV_MEDIUM:
            return "medium"
        return "low"

    def _classify_violation_type(
        self, framework: str, data_sensitivity: str, is_third_party: bool
    ) -> str:
        """Return a violation type label for a framework/context pair.

        Args:
            framework: Regulatory framework name.
            data_sensitivity: Data sensitivity category.
            is_third_party: Whether the endpoint is a third-party processor.

        Returns:
            Violation type string.
        """
        if framework == "HIPAA" and data_sensitivity == "healthcare":
            return "unauthorized_phi_disclosure"
        if framework == "GDPR" and is_third_party:
            return "unauthorized_data_processor"
        if framework == "PCI_DSS" and data_sensitivity == "financial":
            return "cardholder_data_exposure"
        if framework == "SOX" and data_sensitivity in ("financial", "ip"):
            return "financial_data_leak"
        return "unauthorized_external_data_transfer"

    def _build_violation_reason(
        self,
        framework: str,
        data_sensitivity: str,
        api_endpoint: str,
        is_third_party: bool,
    ) -> str:
        """Compose a human-readable violation reason.

        Args:
            framework: Regulatory framework.
            data_sensitivity: Data category.
            api_endpoint: API endpoint domain.
            is_third_party: Whether endpoint is external.

        Returns:
            Violation reason string.
        """
        base = f"{framework} violation: {data_sensitivity.upper()} data"
        if is_third_party:
            base += f" transmitted to unauthorised third-party processor at {api_endpoint}"
        else:
            base += " accessed via unsanctioned AI tool outside enterprise governance controls"
        return base + "."

    def _generate_remediation(
        self,
        violations: list[dict[str, Any]],
        tool_name: str,
        api_endpoint: str,
    ) -> list[str]:
        """Generate prioritised remediation recommendations.

        Args:
            violations: List of violation dicts.
            tool_name: Shadow tool name.
            api_endpoint: API endpoint domain.

        Returns:
            Ordered list of remediation step strings.
        """
        steps: list[str] = []
        frameworks = [v.get("framework") for v in violations]

        steps.append(
            f"Immediately notify the affected employee(s) using {tool_name} "
            f"and block access to {api_endpoint} via network policy."
        )

        if "GDPR" in frameworks or "HIPAA" in frameworks:
            steps.append(
                "Conduct a Data Protection Impact Assessment (DPIA) to determine "
                "whether a breach notification is required within 72 hours."
            )

        if "HIPAA" in frameworks:
            steps.append(
                "Engage the HIPAA Privacy Officer immediately. Document the incident "
                "in the breach log and initiate patient notification assessment."
            )

        steps.append(
            f"Migrate affected user(s) to a governed AI tool via AumOS Migration Service. "
            f"Provision access and complete mandatory data handling training."
        )

        if api_endpoint in _THIRD_PARTY_ENDPOINTS:
            steps.append(
                f"Review whether a Data Processing Agreement (DPA) with {api_endpoint.split('.')[1]} "
                f"is required and whether it is in place."
            )

        steps.append(
            "Update the acceptable use policy and add shadow AI detection coverage "
            "to the next security awareness training cycle."
        )

        return steps
