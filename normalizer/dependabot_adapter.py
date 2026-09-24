import sys
import os
from typing import Any

# Add project root so github_client.py resolves
sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

# import github_client
import normalizer.ocsf_models


class DependabotAdapter:

    def __init__(self, scanner_name: str, scanner_version: str | None = None):
        self.scanner_name = scanner_name
        self.scanner_version = scanner_version


    def map_cvss(self, source: dict) -> list[normalizer.ocsf_models.CVSSObject]:

        advisory = source.get("security_advisory", {})
        cvss_data = advisory.get("cvss_severities", {})

        cvss_list = []

        if isinstance(cvss_data, dict):

            for key, value in cvss_data.items():

                if not isinstance(value, dict):
                    continue

                if key == "cvss_v3":

                    cvss_object = normalizer.ocsf_models.CVSSObject(
                        source="github",
                        v3_score=value.get("score"),
                        v3_vector=value.get("vector_string")
                    )

                    cvss_list.append(cvss_object)

                elif key == "cvss_v4":

                    # Dependabot can return score=0.0/vector=None
                    # when a real CVSS v4 assessment isn't available.
                    vector = value.get("vector_string")
                    score = value.get("score")

                    if vector is not None:
                        cvss_object = normalizer.ocsf_models.CVSSObject(
                            source="github",
                            v4_score=score,
                            v4_vector=vector
                        )

                        cvss_list.append(cvss_object)

        return cvss_list


    def map_vulnerability(
        self,
        source: dict
    ) -> normalizer.ocsf_models.VulnerabilityObject:

        advisory = source.get("security_advisory", {})

        cve_id = advisory.get("cve_id")
        title = advisory.get("summary")
        desc = advisory.get("description")

        # EPSS
        epss = advisory.get("epss") or {}
        epss_score = epss.get("percentage")

        # CWE objects -> list of CWE IDs
        cwe_data = advisory.get("cwes") or []

        cwe_ids = [
            cwe.get("cwe_id")
            for cwe in cwe_data
            if isinstance(cwe, dict) and cwe.get("cwe_id")
        ]

        # Reference objects -> list of URLs
        reference_data = advisory.get("references") or []

        references = [
            ref.get("url")
            for ref in reference_data
            if isinstance(ref, dict) and ref.get("url")
        ]

        cvss = self.map_cvss(source)

        # Dependabot alert number by itself isn't globally unique.
        # Combine advisory/package context with the alert number.
        dependency = source.get("dependency", {})
        package = dependency.get("package", {})

        package_name = package.get("name", "")
        alert_number = source.get("number", "")

        uid = f"dependabot:{package_name}:{alert_number}"

        vulnerability_object = normalizer.ocsf_models.VulnerabilityObject(
            uid=uid,
            cve_id=cve_id,
            title=title,
            desc=desc,
            cvss=cvss,
            vendor_severity={},
            cwe_ids=cwe_ids,
            epss_score=epss_score,
            severity_source="github",
            references=references
        )

        return vulnerability_object


    def map_resource(
        self,
        source: dict
    ) -> normalizer.ocsf_models.ResourceObject:

        security_vulnerability = (
            source.get("security_vulnerability") or {}
        )

        package = security_vulnerability.get("package") or {}

        package_name = package.get("name", "")
        ecosystem = package.get("ecosystem")

        vulnerable_version_range = (
            security_vulnerability.get("vulnerable_version_range")
        )

        patched = (
            security_vulnerability.get("first_patched_version") or {}
        )

        fixed_version = patched.get("identifier")

        resource_object = normalizer.ocsf_models.ResourceObject(
            name=package_name,
            resource_type="package",
            ecosystem=ecosystem,
            vulnerable_version_range=vulnerable_version_range,
            fixed_version=fixed_version
        )

        return resource_object


    def map_product(self) -> normalizer.ocsf_models.ProductObject:

        return normalizer.ocsf_models.ProductObject(
            name=self.scanner_name,
            vendor="GitHub",
            version=self.scanner_version
        )


    def normalizer(
        self,
        source: dict
    ) -> normalizer.ocsf_models.OCSFVulnerabilityFinding:

        advisory = source.get("security_advisory", {})
        dependency = source.get("dependency", {})
        package = dependency.get("package", {})

        alert_number = source.get("number", "")
        package_name = package.get("name", "")

        finding_uid = f"dependabot:{package_name}:{alert_number}"

        severity = advisory.get("severity", "")
        status = source.get("state", "")

        vulnerability = self.map_vulnerability(source)
        resource = self.map_resource(source)
        product = self.map_product()

        source_metadata = {
            "alert_number": source.get("number"),
            "ghsa_id": advisory.get("ghsa_id"),
            "manifest_path": dependency.get("manifest_path"),
            "scope": dependency.get("scope"),
            "relationship": dependency.get("relationship"),
            "classification": advisory.get("classification"),
            "created_at": source.get("created_at"),
            "updated_at": source.get("updated_at"),
            "fixed_at": source.get("fixed_at"),
            "dismissed_at": source.get("dismissed_at"),
            "epss_percentile": (
                (advisory.get("epss") or {}).get("percentile")
            )
        }

        return normalizer.ocsf_models.OCSFVulnerabilityFinding(
            finding_uid=finding_uid,
            severity=severity,
            status=status,
            vulnerabilities=[vulnerability],
            resources=[resource],
            product=[product],
            source_metadata=source_metadata
        )


# --------------------------------------------------
# Fetch + normalize all Dependabot alerts
# --------------------------------------------------

# alerts = github_client.fetch_dependabot_alerts()

# dependabot = DependabotAdapter(
#     scanner_name="Dependabot",
#     scanner_version=None)

# normalized_dependabot_findings = []

# for alert in alerts:
#     normalized_finding = dependabot.normalizer(alert)
#     normalized_dependabot_findings.append(normalized_finding)


# print("Raw Dependabot alerts:", len(alerts))
# print(
#     "Normalized Dependabot findings:",
#     len(normalized_dependabot_findings)
# )

# for finding in normalized_dependabot_findings:
#     print(finding)

