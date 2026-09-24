### VulnOps AI main application file. This file sets up the FastAPI application, defines routes for syncing and enriching vulnerability data, and provides endpoints for querying findings and risks.

from fastapi import FastAPI, Depends
import models
from database import engine
from sqlalchemy.orm import Session
from database import get_db
from github_client import fetch_dependabot_alerts
# from sync_service import sync_dependabot_alerts
from normalizer.dependabot_adapter import DependabotAdapter
from sync_service import sync_findings_to_db
import os
import time
from nvd_client import fetch_cve_from_nvd
from cisa_client import fetch_kev_catalog
from rag_service import embed_and_store_cves
from rag_service import query_vulnerabilities_semantic
from normalizer.trivy_adapter import TrivyAdapter

import contextlib
# from mcp_server import mcp
from fastapi import UploadFile, File
# from trivy_client import parse_trivy_report
# from sync_service import sync_trivy_findings
import json
models.Base.metadata.create_all(bind=engine)




from services.finding_service import get_open_findings
from services.finding_service import get_kev_findings
from services.finding_service import get_top_risks






# # Build the MCP HTTP app and lifespan BEFORE creating the FastAPI app
# mcp_app = mcp.streamable_http_app()

# @contextlib.asynccontextmanager
# async def lifespan(app: FastAPI):
#     async with mcp.session_manager.run():
#         yield

# Create the app ONCE, with lifespan wired in from the start
app = FastAPI(title="VulnOps AI")#lifespan=lifespan)


@app.get("/")
def read_root():
    return {"message": "VulnOps AI is running"}

@app.post("/sync/dependabot")
def sync_dependabot(db: Session = Depends(get_db)):
    # Fetch raw Dependabot alerts
    alerts = fetch_dependabot_alerts()
    # Create Dependabot OCSF adapter
    adapter = DependabotAdapter(
        scanner_name="Dependabot",
        scanner_version=None
    )
    # Normalize all raw Dependabot alerts
    normalized_findings = [
        adapter.normalizer(alert)
        for alert in alerts
    ]
    # Store normalized findings using generic DB sync
    count = sync_findings_to_db(
        normalized_findings,
        os.getenv("GITHUB_REPO_NAME"),
        os.getenv("GITHUB_REPO_OWNER"),
        db
    )

    return {
        "synced_findings": count,
        "total_alerts_received": len(alerts),
        "normalized_findings": len(normalized_findings)
    }
    
@app.post("/sync/enrich")
def enrich_cves(db: Session = Depends(get_db)):
    kev_set = fetch_kev_catalog()
    cves = db.query(models.CVE).all()
    enriched_count = 0

    for cve in cves:
        exploitable_cve = cve.cve_id in kev_set
        cve.is_kev = exploitable_cve

        if cve.cvss_score is None:
            nvd_data = fetch_cve_from_nvd(cve.cve_id)
            if nvd_data and nvd_data["cvss_score"]:
                cve.cvss_score = nvd_data["cvss_score"]
                cve.cvss_version = nvd_data["cvss_version"]
            time.sleep(6)

        enriched_count += 1

    db.commit()
    return {"enriched": enriched_count, "kev_matches": sum(1 for c in cves if c.is_kev)}

@app.post("/sync/trivy")
async def sync_trivy(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    data = json.loads(contents)

    # Extract raw Trivy vulnerability objects
    alerts = []

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            alerts.append(vuln)

    # Create Trivy OCSF adapter
    adapter = TrivyAdapter(
        scanner_name="Trivy",
        scanner_version=None
    )

    # Raw Trivy → OCSF
    normalized_findings = [
        adapter.normalizer(alert)
        for alert in alerts
    ]

    # OCSF → database
    count = sync_findings_to_db(
        normalized_findings,
        os.getenv("GITHUB_REPO_NAME"),
        os.getenv("GITHUB_REPO_OWNER"),
        db
    )

    return {
        "synced_findings": count,
        "total_alerts_received": len(alerts),
        "normalized_findings": len(normalized_findings)
    }


from epss_client import fetch_epss_scores

@app.post("/sync/epss")
def sync_epss(db: Session = Depends(get_db)):
    cves = db.query(models.CVE).all()
    cve_ids = [c.cve_id for c in cves]

    scores = {}
    chunk_size = 50
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        scores.update(fetch_epss_scores(chunk))

    updated = 0
    for cve in cves:
        if cve.cve_id in scores:
            cve.epss_score = scores[cve.cve_id]
            updated += 1

    db.commit()
    return {"updated": updated, "total_cves": len(cves)}
    


@app.post("/sync/embed")
def sync_embed(db: Session = Depends(get_db)):
    return embed_and_store_cves(db)



from risk_engine import calculate_risk_score

@app.get("/risk/top")
def top_risks(limit: int = 20, db: Session = Depends(get_db)):
    findings = db.query(models.Findings).filter(models.Findings.status == "open").all()

    scored = []
    for f in findings:
        score = calculate_risk_score(f, f.cve, f.repository)
        scored.append({
            "cve_id": f.cve.cve_id,
            "severity": f.cve.severity,
            "cvss_score": f.cve.cvss_score,
            "epss_score": f.cve.epss_score,
            "is_kev": f.cve.is_kev,
            "affected_package": f.affected_package,
            "source": f.source,
            "repository": f.repository.name,
            "risk_score": score
        })

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"top_risks": scored[:limit], "total_findings_scored": len(scored)}




# class QuestionRequest(BaseModel):
#     question: str

# @app.post("/ask")
# def ask_question(request: QuestionRequest):
#     return query_vulnerabilities_semantic(request.question)

# @app.post("/get_top_risks")
# def ask_question(request: QuestionRequest):
#     return query_vulnerabilities_semantic(request.question)



# Mount MCP LAST, after every other route is registered
# app.mount("", mcp_app)


@app.get("/api/v1/findings/open")
def open_findings(
    db: Session = Depends(get_db)
):
    return get_open_findings(db)


@app.get("/api/v1/findings/kev_findings")
def kev_findings(
    db: Session = Depends(get_db)
):
    return get_kev_findings(db)


@app.get("/api/v1/risks/top")
def top_risks(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    return get_top_risks(db, limit)

from pydantic import BaseModel
class VulnerabilityQuestion(BaseModel):
    question: str

@app.post("/api/v1/vulnerabilities/query")
def ask_vulnerability_question(
    request:  VulnerabilityQuestion
):
    return query_vulnerabilities_semantic(
        request.question
    )




























# ### VulnOps AI main application file. This file sets up the FastAPI application, defines routes for syncing and enriching vulnerability data, and provides endpoints for querying findings and risks.

# from fastapi import FastAPI, Depends
# import models
# from database import engine
# from sqlalchemy.orm import Session
# from database import get_db
# from github_client import fetch_dependabot_alerts
# from sync_service import sync_dependabot_alerts
# import os
# import time
# from nvd_client import fetch_cve_from_nvd
# from cisa_client import fetch_kev_catalog
# from rag_service import embed_and_store_cves
# from rag_service import query_vulnerabilities_semantic

# import contextlib
# # from mcp_server import mcp
# from fastapi import UploadFile, File
# from trivy_client import parse_trivy_report
# from sync_service import sync_trivy_findings
# import json
# models.Base.metadata.create_all(bind=engine)




# from services.finding_service import get_open_findings
# from services.finding_service import get_kev_findings
# from services.finding_service import get_top_risks






# # # Build the MCP HTTP app and lifespan BEFORE creating the FastAPI app
# # mcp_app = mcp.streamable_http_app()

# # @contextlib.asynccontextmanager
# # async def lifespan(app: FastAPI):
# #     async with mcp.session_manager.run():
# #         yield

# # Create the app ONCE, with lifespan wired in from the start
# app = FastAPI(title="VulnOps AI")#lifespan=lifespan)


# @app.get("/")
# def read_root():
#     return {"message": "VulnOps AI is running"}


# @app.post("/sync/dependabot")
# def sync_dependabot(db: Session = Depends(get_db)):
#     alerts = fetch_dependabot_alerts()
#     count = sync_dependabot_alerts(
#         alerts,
#         os.getenv("GITHUB_REPO_OWNER"),
#         os.getenv("GITHUB_REPO_NAME"),
#         db
#     )
#     return {"synced_findings": count, "total_alerts_received": len(alerts)}


# @app.post("/sync/enrich")
# def enrich_cves(db: Session = Depends(get_db)):
#     kev_set = fetch_kev_catalog()
#     cves = db.query(models.CVE).all()
#     enriched_count = 0

#     for cve in cves:
#         exploitable_cve = cve.cve_id in kev_set
#         cve.is_kev = exploitable_cve

#         if cve.cvss_score is None:
#             nvd_data = fetch_cve_from_nvd(cve.cve_id)
#             if nvd_data and nvd_data["cvss_score"]:
#                 cve.cvss_score = nvd_data["cvss_score"]
#                 cve.cvss_version = nvd_data["cvss_version"]
#             time.sleep(6)

#         enriched_count += 1

#     db.commit()
#     return {"enriched": enriched_count, "kev_matches": sum(1 for c in cves if c.is_kev)}

# @app.post("/sync/trivy")
# async def sync_trivy(file: UploadFile = File(...), db: Session = Depends(get_db)):
#     contents = await file.read()          # read raw bytes from the upload
#     data = json.loads(contents)     # parse those bytes into a Python dict

#     alerts = parse_trivy_report(data)      # now pass the parsed dict, not the UploadFile
#     count = sync_trivy_findings(
#         alerts,
#         os.getenv("GITHUB_REPO_OWNER"),
#         os.getenv("GITHUB_REPO_NAME"),
#         db
#     )
#     return {"synced_findings": count, "total_alerts_received": len(alerts)}


# from epss_client import fetch_epss_scores

# @app.post("/sync/epss")
# def sync_epss(db: Session = Depends(get_db)):
#     cves = db.query(models.CVE).all()
#     cve_ids = [c.cve_id for c in cves]

#     scores = {}
#     chunk_size = 50
#     for i in range(0, len(cve_ids), chunk_size):
#         chunk = cve_ids[i:i + chunk_size]
#         scores.update(fetch_epss_scores(chunk))

#     updated = 0
#     for cve in cves:
#         if cve.cve_id in scores:
#             cve.epss_score = scores[cve.cve_id]
#             updated += 1

#     db.commit()
#     return {"updated": updated, "total_cves": len(cves)}
    


# @app.post("/sync/embed")
# def sync_embed(db: Session = Depends(get_db)):
#     return embed_and_store_cves(db)



# from risk_engine import calculate_risk_score

# @app.get("/risk/top")
# def top_risks(limit: int = 20, db: Session = Depends(get_db)):
#     findings = db.query(models.Findings).filter(models.Findings.status == "open").all()

#     scored = []
#     for f in findings:
#         score = calculate_risk_score(f, f.cve, f.repository)
#         scored.append({
#             "cve_id": f.cve.cve_id,
#             "severity": f.cve.severity,
#             "cvss_score": f.cve.cvss_score,
#             "epss_score": f.cve.epss_score,
#             "is_kev": f.cve.is_kev,
#             "affected_package": f.affected_package,
#             "source": f.source,
#             "repository": f.repository.name,
#             "risk_score": score
#         })

#     scored.sort(key=lambda x: x["risk_score"], reverse=True)
#     return {"top_risks": scored[:limit], "total_findings_scored": len(scored)}




# # class QuestionRequest(BaseModel):
# #     question: str

# # @app.post("/ask")
# # def ask_question(request: QuestionRequest):
# #     return query_vulnerabilities_semantic(request.question)

# # @app.post("/get_top_risks")
# # def ask_question(request: QuestionRequest):
# #     return query_vulnerabilities_semantic(request.question)



# # Mount MCP LAST, after every other route is registered
# # app.mount("", mcp_app)


# @app.get("/api/v1/findings/open")
# def open_findings(
#     db: Session = Depends(get_db)
# ):
#     return get_open_findings(db)


# @app.get("/api/v1/findings/kev_findings")
# def kev_findings(
#     db: Session = Depends(get_db)
# ):
#     return get_kev_findings(db)


# @app.get("/api/v1/risks/top")
# def top_risks(
#     limit: int = 10,
#     db: Session = Depends(get_db)
# ):
#     return get_top_risks(db, limit)

# from pydantic import BaseModel
# class VulnerabilityQuestion(BaseModel):
#     question: str

# @app.post("/api/v1/vulnerabilities/query")
# def ask_vulnerability_question(
#     request:  VulnerabilityQuestion
# ):
#     return query_vulnerabilities_semantic(
#         request.question
#     )