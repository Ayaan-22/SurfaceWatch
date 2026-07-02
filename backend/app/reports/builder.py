from pathlib import Path

from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Change, Finding, Port, Project, Report, Scan, SecurityHeader, SslResult, Technology
from app.scanner.report_builder import AUTHORIZED_USE_DISCLAIMER


REPORT_DIR = Path("generated_reports")


def _safe_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()


def build_pdf_report(db: Session, project: Project, report: Report) -> Path:
    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / f"surfacewatch-{project.id}-{report.id}.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=letter, title=f"SurfaceWatch Report - {project.company_name}")
    findings = list(db.scalars(select(Finding).where(Finding.project_id == project.id).order_by(Finding.severity.desc())))
    assets = list(db.scalars(select(Asset).where(Asset.project_id == project.id).order_by(Asset.hostname.asc())))
    latest_scan = db.scalar(select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc()))

    story = [
        Paragraph("SurfaceWatch Exposure Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Project: {_safe_text(project.company_name)}", styles["Heading2"]),
        Paragraph(f"Domain: {_safe_text(project.main_domain)}", styles["Normal"]),
        Paragraph(f"Overall risk score: {project.risk_score} ({project.risk_level})", styles["Normal"]),
        Paragraph(f"Latest scan: {_safe_text(latest_scan.id if latest_scan else 'No scan yet')}", styles["Normal"]),
        Spacer(1, 16),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(
            f"SurfaceWatch identified {len(assets)} tracked assets and {len(findings)} findings for this authorized project.",
            styles["Normal"],
        ),
        Spacer(1, 12),
        Paragraph("Top Findings", styles["Heading2"]),
    ]

    finding_rows = [["Severity", "Category", "Title", "Status"]]
    for finding in findings[:20]:
        finding_rows.append([finding.severity, finding.category, finding.title, finding.status])
    if len(finding_rows) == 1:
        finding_rows.append(["-", "-", "No findings recorded.", "-"])
    finding_table = Table(finding_rows, repeatRows=1, colWidths=[70, 110, 250, 70])
    finding_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.extend([finding_table, Spacer(1, 16), Paragraph("Authorization Disclaimer", styles["Heading2"])])
    story.append(Paragraph(AUTHORIZED_USE_DISCLAIMER, styles["Normal"]))
    doc.build(story)
    return path


def build_excel_report(db: Session, project: Project, report: Report) -> Path:
    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / f"surfacewatch-{project.id}-{report.id}.xlsx"
    workbook = Workbook()

    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Project", project.company_name])
    summary.append(["Domain", project.main_domain])
    summary.append(["Risk Score", project.risk_score])
    summary.append(["Risk Level", project.risk_level])
    summary.append(["Disclaimer", AUTHORIZED_USE_DISCLAIMER])

    sheets = {
        "Assets": ["Hostname", "Type", "IP", "Status", "Risk", "First Seen", "Last Seen"],
        "Findings": ["Severity", "Category", "Title", "Status", "Asset ID", "Last Seen"],
        "Open Ports": ["Asset ID", "Port", "Protocol", "Status", "Service", "Banner"],
        "Security Headers": ["Asset ID", "Header", "Present", "Value", "Risk", "Recommendation"],
        "SSL TLS": ["Asset ID", "Issuer", "Common Name", "Valid Until", "Days Until Expiry", "Status"],
        "Technologies": ["Asset ID", "Name", "Category", "Confidence", "Evidence"],
        "Changes": ["Asset ID", "Change Type", "Old Value", "New Value", "Severity", "Detected At"],
        "Scan Metadata": ["Scan ID", "Status", "Started", "Finished", "Assets", "Findings", "Risk Score"],
    }
    for title, headers in sheets.items():
        sheet = workbook.create_sheet(title)
        sheet.append(headers)

    for asset in db.scalars(select(Asset).where(Asset.project_id == project.id).order_by(Asset.hostname.asc())):
        workbook["Assets"].append([asset.hostname, asset.asset_type, asset.ip_address, asset.status, asset.risk_level, _safe_text(asset.first_seen_at), _safe_text(asset.last_seen_at)])
    for finding in db.scalars(select(Finding).where(Finding.project_id == project.id).order_by(Finding.last_seen_at.desc())):
        workbook["Findings"].append([finding.severity, finding.category, finding.title, finding.status, finding.asset_id, _safe_text(finding.last_seen_at)])
    for port in db.scalars(select(Port).where(Port.project_id == project.id).order_by(Port.port.asc())):
        workbook["Open Ports"].append([port.asset_id, port.port, port.protocol, port.status, port.service_guess, port.banner])
    for header in db.scalars(select(SecurityHeader).where(SecurityHeader.project_id == project.id).order_by(SecurityHeader.header_name.asc())):
        workbook["Security Headers"].append([header.asset_id, header.header_name, header.present, header.value, header.risk_level, header.recommendation])
    for ssl_result in db.scalars(select(SslResult).where(SslResult.project_id == project.id)):
        workbook["SSL TLS"].append([ssl_result.asset_id, ssl_result.issuer, ssl_result.subject_common_name, _safe_text(ssl_result.valid_until), ssl_result.days_until_expiry, ssl_result.status])
    for technology in db.scalars(select(Technology).where(Technology.project_id == project.id).order_by(Technology.name.asc())):
        workbook["Technologies"].append([technology.asset_id, technology.name, technology.category, technology.confidence, technology.evidence])
    for change in db.scalars(select(Change).where(Change.project_id == project.id).order_by(Change.detected_at.desc())):
        workbook["Changes"].append([change.asset_id, change.change_type, change.old_value, change.new_value, change.severity, _safe_text(change.detected_at)])
    for scan in db.scalars(select(Scan).where(Scan.project_id == project.id).order_by(Scan.created_at.desc())):
        workbook["Scan Metadata"].append([scan.id, scan.status, _safe_text(scan.started_at), _safe_text(scan.finished_at), scan.assets_scanned, scan.findings_created, scan.risk_score])

    workbook.save(path)
    return path
