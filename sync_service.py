from sqlalchemy.orm import Session
from datetime import datetime
import models
import normalizer.ocsf_models


def sync_findings_to_db(
    findings: list[normalizer.ocsf_models.OCSFVulnerabilityFinding],
    repo_name: str,
    repo_owner: str,
    db: Session
) -> int:

    """
    Sync normalized OCSF vulnerability findings into the database.

    The sync layer does not know whether the original finding
    came from Trivy, Dependabot, or another scanner.
    """

    # ---------------------------------------------------------
    # 1. Get or create repository
    # ---------------------------------------------------------

    repo = db.query(models.Repository).filter(
        models.Repository.name == repo_name,
        models.Repository.owner == repo_owner
    ).first()

    if not repo:
        repo = models.Repository(
            name=repo_name,
            owner=repo_owner,
            url=f"https://github.com/{repo_owner}/{repo_name}"
        )

        db.add(repo)
        db.commit()
        db.refresh(repo)

    synced_count = 0

    # ---------------------------------------------------------
    # 2. Process every normalized finding
    # ---------------------------------------------------------

    for finding in findings:

        # Our current adapters produce one vulnerability,
        # one resource and one product per finding.
        if not finding.vulnerabilities or not finding.resources:
            continue

        vulnerability = finding.vulnerabilities[0]
        resource = finding.resources[0]

        product = finding.product[0] if finding.product else None

        # -----------------------------------------------------
        # 3. Extract normalized OCSF fields
        # -----------------------------------------------------

        cve_id = vulnerability.cve_id

        # Skip GHSA-only / non-CVE findings for now
        if not cve_id or not cve_id.startswith("CVE-"):
            continue

        description = vulnerability.desc
        epss_score = vulnerability.epss_score

        severity = finding.severity

        package_name = resource.name
        affected_version = resource.installed_version

        status = finding.status or "open"

        source = product.name.lower() if product else "unknown"

        # -----------------------------------------------------
        # 4. Get or create CVE
        # -----------------------------------------------------

        cve = db.query(models.CVE).filter(
            models.CVE.cve_id == cve_id
        ).first()

        if not cve:

            cve = models.CVE(
                cve_id=cve_id,
                description=description,
                severity=severity.upper() if severity else None,
                epss_score=epss_score
            )

            db.add(cve)
            db.commit()
            db.refresh(cve)

        # -----------------------------------------------------
        # 5. Check whether this scanner finding already exists
        # -----------------------------------------------------

        existing_finding = db.query(models.Findings).filter(
            models.Findings.cve_id == cve.id,
            models.Findings.repository_id == repo.id,
            models.Findings.affected_package == package_name,
            models.Findings.source == source
        ).first()

        # -----------------------------------------------------
        # 6. Create finding
        # -----------------------------------------------------

        if not existing_finding:

            db_finding = models.Findings(
                cve_id=cve.id,
                repository_id=repo.id,
                affected_package=package_name,
                affected_version=affected_version,
                status=status,
                source=source
            )

            db.add(db_finding)
            db.commit()

            synced_count += 1

    return synced_count






        
















































































































# def sync_dependabot_alerts(alerts: list, repo_owner: str, repo_name: str, db: Session):
#     # Get or create the repository row
#     repo = db.query(models.Repository).filter(
#         models.Repository.name == repo_name,
#         models.Repository.owner == repo_owner
#     ).first()

#     if not repo:
#         repo = models.Repository(
#             name=repo_name,
#             owner=repo_owner,
#             url=f"https://github.com/{repo_owner}/{repo_name}"
#         )
#         db.add(repo)
#         db.commit()
#         db.refresh(repo)

#     synced_count = 0

#     for alert in alerts:
#         advisory = alert.get("security_advisory", {})
#         cve_id = advisory.get("cve_id")

#         if not cve_id:
#             continue  # some advisories use GHSA IDs only, skip for now

#         # Get or create the CVE row
#         cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()
#         if not cve:
#             severity = advisory.get("severity", "").upper()
#             cvss = advisory.get("cvss", {}).get("score")
#             published = advisory.get("published_at")

#             cve = models.CVE(
#                 cve_id=cve_id,
#                 description=advisory.get("summary", ""),
#                 cvss_score=cvss,
#                 severity=severity,
#                 published_date=datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
#             )
#             db.add(cve)
#             db.commit()
#             db.refresh(cve)

#         # Get or create the Finding row (avoid duplicate findings for same cve+repo+package)
#         package_name = alert.get("dependency", {}).get("package", {}).get("name", "unknown")

#         existing_finding = db.query(models.Findings).filter(
#             models.Findings.cve_id == cve.id,
#             models.Findings.repository_id == repo.id,
#             models.Findings.affected_package == package_name
#         ).first()

#         if not existing_finding:
#             finding = models.Findings(
#                 cve_id=cve.id,
#                 repository_id=repo.id,
#                 affected_package=package_name,
#                 affected_version=alert.get("dependency", {}).get("manifest_path", ""),
#                 status=alert.get("state", "open")
#             )
#             db.add(finding)
#             db.commit()
#             synced_count += 1

#     return synced_count


# def sync_trivy_findings(trivy_vulns: list[dict], repo_owner: str, repo_name: str, db: Session) -> int:
#     repo = db.query(models.Repository).filter(
#         models.Repository.name == repo_name,
#         models.Repository.owner == repo_owner
#     ).first()

#     if not repo:
#         repo = models.Repository(
#             name=repo_name,
#             owner=repo_owner,
#             url=f"https://github.com/{repo_owner}/{repo_name}"
#         )
#         db.add(repo)
#         db.commit()
#         db.refresh(repo)

#     synced_count = 0

#     for vuln in trivy_vulns:
#         cve_id_str = vuln["cve_id"]
#         if not cve_id_str or not cve_id_str.startswith("CVE-"):
#             continue  # skip non-CVE advisories (e.g. Trivy sometimes reports GHSA-only entries)

#         cve = db.query(models.CVE).filter(models.CVE.cve_id == cve_id_str).first()
#         if not cve:
#             cve = models.CVE(
#                 cve_id=cve_id_str,
#                 description=vuln["description"][:1000],  # keep descriptions reasonably sized
#                 severity=vuln["severity"],
#             )
#             db.add(cve)
#             db.commit()
#             db.refresh(cve)

#         existing_finding = db.query(models.Findings).filter(
#             models.Findings.cve_id == cve.id,
#             models.Findings.repository_id == repo.id,
#             models.Findings.affected_package == vuln["package"],
#             models.Findings.source == "trivy"
#         ).first()

#         if not existing_finding:
#             finding = models.Findings(
#                 cve_id=cve.id,
#                 repository_id=repo.id,
#                 affected_package=vuln["package"],
#                 affected_version=vuln["installed_version"],
#                 status="open",
#                 source="trivy"
#             )
#             db.add(finding)
#             db.commit()
#             synced_count += 1

#     return synced_count