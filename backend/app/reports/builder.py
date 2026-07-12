import json
from pathlib import Path
from xml.sax.saxutils import escape

from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Change, Finding, Port, Project, Report, Scan, ScanAssetResult, SecurityHeader, SslResult, Technology
from app.scanner.report_builder import AUTHORIZED_USE_DISCLAIMER


REPORT_DIR = Path("generated_reports")


def _safe_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()


def _pdf_text(value: object) -> str:
    return escape(_safe_text(value))


def _excel_value(value: object):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, default=str)
    text = _safe_text(value)
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _scan_result_rows(db: Session, scan: Scan) -> list[ScanAssetResult]:
    return list(
        db.scalars(
            select(ScanAssetResult)
            .where(ScanAssetResult.scan_id == scan.id)
            .order_by(ScanAssetResult.hostname.asc())
        )
    )


def _snapshot_findings(result_rows: list[ScanAssetResult]) -> list[dict]:
    findings: list[dict] = []
    for row in result_rows:
        for observation in row.finding_observations or []:
            if not isinstance(observation, dict):
                continue
            findings.append({**observation, "asset_id": row.asset_id, "asset_hostname": row.hostname})
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(str(finding.get("severity", "info")).lower(), 99),
            str(finding.get("asset_hostname", "")),
            str(finding.get("title", "")),
        ),
    )


def _report_scan(db: Session, project: Project, report: Report) -> Scan:
    if report.scan_id is None:
        raise ValueError("Report is missing a scan_id.")
    scan = db.get(Scan, report.scan_id)
    if scan is None or scan.project_id != project.id:
        raise ValueError("Report scan does not belong to this project.")
    return scan


def _scan_date(scan: Scan):
    return scan.finished_at or scan.started_at or scan.created_at


def build_pdf_report(db: Session, project: Project, report: Report) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    scan = _report_scan(db, project, report)
    path = REPORT_DIR / f"surfacewatch-{project.id}-{scan.id}-{report.id}.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=letter, title=f"SurfaceWatch Report - {project.company_name} - {scan.scan_profile} scan")
    result_rows = _scan_result_rows(db, scan)
    if result_rows:
        findings = _snapshot_findings(result_rows)
        asset_count = len(result_rows)
    else:
        legacy_findings = list(db.scalars(select(Finding).where(Finding.project_id == project.id, Finding.scan_id == scan.id)))
        findings = [
            {
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "status": finding.status,
                "asset_hostname": finding.asset_hostname,
                "description": finding.description,
                "recommendation": finding.recommendation,
            }
            for finding in legacy_findings
        ]
        findings.sort(key=lambda finding: SEVERITY_ORDER.get(str(finding["severity"]).lower(), 99))
        asset_count = len(list(db.scalars(select(Asset.id).where(Asset.project_id == project.id, Asset.scan_id == scan.id))))

    story = [
        Paragraph("SurfaceWatch Exposure Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Project: {_pdf_text(project.company_name)}", styles["Heading2"]),
        Paragraph(f"Domain: {_pdf_text(project.main_domain)}", styles["Normal"]),
        Paragraph(f"Scan: {_pdf_text(scan.scan_profile).title()} profile on {_pdf_text(_scan_date(scan))}", styles["Normal"]),
        Paragraph(f"Scan ID: {_pdf_text(scan.id)}", styles["Normal"]),
        Paragraph(f"Scan risk score: {scan.risk_score}", styles["Normal"]),
        Paragraph(f"Scan status: {_pdf_text(scan.status)}", styles["Normal"]),
        Paragraph(f"Coverage: {scan.coverage_percent}% ({scan.assets_scanned}/{scan.assets_discovered} candidates processed)", styles["Normal"]),
        Paragraph(f"Execution attempt: {scan.attempt_count}", styles["Normal"]),
        Spacer(1, 16),
        Paragraph("Executive Summary", styles["Heading2"]),
        Paragraph(
            f"SurfaceWatch recorded {asset_count} target manifests and {len(findings)} finding observations in the selected scan.",
            styles["Normal"],
        ),
        Spacer(1, 12),
    ]

    if scan.partial_reason:
        story.extend(
            [
                Paragraph("Coverage Warning", styles["Heading2"]),
                Paragraph(_pdf_text(scan.partial_reason), styles["Normal"]),
                Spacer(1, 12),
            ]
        )
    story.append(Paragraph("All Findings", styles["Heading2"]))

    finding_rows = [["Severity", "Asset", "Category", "Title", "Status"]]
    for finding in findings:
        finding_rows.append(
            [
                _pdf_text(finding.get("severity", "")),
                Paragraph(_pdf_text(finding.get("asset_hostname", "")), styles["BodyText"]),
                Paragraph(_pdf_text(finding.get("category", "")), styles["BodyText"]),
                Paragraph(_pdf_text(finding.get("title", "")), styles["BodyText"]),
                _pdf_text(finding.get("status", "open")),
            ]
        )
    if len(finding_rows) == 1:
        finding_rows.append(["-", "-", "-", "No findings recorded.", "-"])
    finding_table = Table(finding_rows, repeatRows=1, colWidths=[52, 92, 88, 210, 54])
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
    story.extend([finding_table, Spacer(1, 16)])
    if findings:
        story.append(Paragraph("Finding Details and Recommendations", styles["Heading2"]))
        for finding in findings:
            evidence = finding.get("evidence")
            evidence_text = json.dumps(evidence, sort_keys=True, default=str) if isinstance(evidence, (dict, list)) else evidence
            story.extend(
                [
                    Paragraph(
                        f"{_pdf_text(finding.get('severity', '')).upper()} — {_pdf_text(finding.get('title', 'Untitled finding'))}",
                        styles["Heading3"],
                    ),
                    Paragraph(
                        f"Asset: {_pdf_text(finding.get('asset_hostname', ''))} | Category: {_pdf_text(finding.get('category', ''))}",
                        styles["Normal"],
                    ),
                    Paragraph(_pdf_text(finding.get("description", "")), styles["Normal"]),
                    Paragraph(
                        f"Business impact: {_pdf_text(finding.get('business_impact', 'Review the affected control and validate the organizational impact.'))}",
                        styles["Normal"],
                    ),
                    Paragraph(f"Evidence: {_pdf_text(evidence_text or 'No additional evidence recorded.')}", styles["Normal"]),
                    Paragraph(
                        f"Recommendation: {_pdf_text(finding.get('recommendation', 'Review and remediate the observed control gap.'))}",
                        styles["Normal"],
                    ),
                    Spacer(1, 8),
                ]
            )
    story.extend([Spacer(1, 8), Paragraph("Target Coverage Appendix", styles["Heading2"])])
    target_table_rows = [["Hostname", "Discovery", "Scan", "Risk", "IP addresses", "Source"]]
    if result_rows:
        for result in result_rows:
            target_table_rows.append(
                [
                    Paragraph(_pdf_text(result.hostname), styles["BodyText"]),
                    _pdf_text(result.discovery_status),
                    _pdf_text(result.scan_status),
                    _pdf_text(result.risk_level),
                    Paragraph(_pdf_text(", ".join(result.ip_addresses or [])), styles["BodyText"]),
                    Paragraph(_pdf_text(result.source), styles["BodyText"]),
                ]
            )
    else:
        for asset in db.scalars(
            select(Asset).where(Asset.project_id == project.id, Asset.scan_id == scan.id).order_by(Asset.hostname.asc())
        ):
            target_table_rows.append(
                [
                    Paragraph(_pdf_text(asset.hostname), styles["BodyText"]),
                    _pdf_text(asset.status),
                    "completed",
                    _pdf_text(asset.risk_level),
                    Paragraph(_pdf_text(asset.ip_address), styles["BodyText"]),
                    Paragraph(_pdf_text(asset.source), styles["BodyText"]),
                ]
            )
    if len(target_table_rows) == 1:
        target_table_rows.append(["-", "-", "-", "-", "No targets recorded.", "-"])
    target_table = Table(target_table_rows, repeatRows=1, colWidths=[118, 62, 55, 48, 120, 93])
    target_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.extend([target_table, Spacer(1, 16)])
    story.append(Paragraph("Authorization Disclaimer", styles["Heading2"]))
    story.append(Paragraph(AUTHORIZED_USE_DISCLAIMER, styles["Normal"]))
    doc.build(story)
    return path


def build_excel_report(db: Session, project: Project, report: Report) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    scan = _report_scan(db, project, report)
    path = REPORT_DIR / f"surfacewatch-{project.id}-{scan.id}-{report.id}.xlsx"
    workbook = Workbook()

    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Project", project.company_name])
    summary.append(["Domain", project.main_domain])
    summary.append(["Scan ID", scan.id])
    summary.append(["Scan Profile", scan.scan_profile])
    summary.append(["Scan Date", _safe_text(_scan_date(scan))])
    summary.append(["Scan Status", scan.status])
    summary.append(["Scan Risk Score", scan.risk_score])
    summary.append(["Coverage Percent", scan.coverage_percent])
    summary.append(["Assets Discovered", scan.assets_discovered])
    summary.append(["Assets Processed", scan.assets_scanned])
    summary.append(["Assets Failed", scan.assets_failed])
    summary.append(["Checks Completed", scan.checks_completed])
    summary.append(["Checks Failed", scan.checks_failed])
    summary.append(["Execution Attempt", scan.attempt_count])
    summary.append(["Last Heartbeat", _safe_text(scan.heartbeat_at)])
    summary.append(["Partial Reason", _excel_value(scan.partial_reason)])
    summary.append(["Disclaimer", AUTHORIZED_USE_DISCLAIMER])

    sheets = {
        "Assets": ["Hostname", "Type", "IP", "Discovery Status", "Scan Status", "Risk", "First Seen", "Last Seen"],
        "Findings": ["Severity", "Category", "Title", "Status", "Asset ID", "Last Seen"],
        "Open Ports": ["Asset ID", "Port", "Protocol", "Status", "Service", "Banner"],
        "Port Results": ["Asset ID", "Port", "Protocol", "Status", "Service", "Banner", "Error"],
        "HTTP Endpoints": ["Asset ID", "Requested URL", "Final URL", "Status Code", "TLS Verified", "Response Time MS", "Captured Bytes", "Redirect Chain", "Error"],
        "Security Headers": ["Asset ID", "Header", "Present", "Value", "Risk", "Recommendation", "Endpoint", "Rule ID", "Issue"],
        "SSL TLS": ["Asset ID", "Port", "Issuer", "Common Name", "Valid Until", "Days Until Expiry", "Status", "TLS Version", "Cipher", "Verified", "Error"],
        "Technologies": ["Asset ID", "Name", "Category", "Confidence", "Evidence", "Endpoint"],
        "Exposure Checks": ["Asset ID", "Requested URL", "Final URL", "Path", "Status Code", "Content Type", "Captured Bytes", "TLS Verified", "Response Time MS", "Redirect Chain", "Error"],
        "Changes": ["Asset ID", "Change Type", "Old Value", "New Value", "Severity", "Detected At"],
        "Target Diagnostics": ["Hostname", "Discovery Status", "Scan Status", "Source", "IP Addresses", "Checks", "Errors"],
        "Scan Metadata": ["Scan ID", "Status", "Started", "Finished", "Attempt", "Heartbeat", "Discovered", "Processed", "Failed", "Findings", "Checks Complete", "Checks Failed", "Coverage", "Risk Score"],
    }
    for title, headers in sheets.items():
        sheet = workbook.create_sheet(title)
        sheet.append(headers)

    result_rows = _scan_result_rows(db, scan)
    if result_rows:
        for result in result_rows:
            workbook["Assets"].append(
                [
                    _excel_value(result.hostname),
                    "domain" if result.hostname == project.main_domain else "subdomain",
                    _excel_value(", ".join(result.ip_addresses or [])),
                    result.discovery_status,
                    result.scan_status,
                    result.risk_level,
                    _safe_text(result.started_at or result.created_at),
                    _safe_text(result.finished_at or result.updated_at),
                ]
            )
            workbook["Target Diagnostics"].append(
                [
                    _excel_value(result.hostname),
                    result.discovery_status,
                    result.scan_status,
                    _excel_value(result.source),
                    _excel_value(result.ip_addresses),
                    _excel_value(result.checks),
                    _excel_value(result.errors),
                ]
            )
            for http in result.http_observations or []:
                if isinstance(http, dict):
                    workbook["HTTP Endpoints"].append(
                        [
                            _excel_value(result.asset_id or result.hostname),
                            _excel_value(http.get("requested_url")),
                            _excel_value(http.get("url")),
                            http.get("status_code"),
                            http.get("tls_verified"),
                            http.get("response_time_ms"),
                            http.get("content_length"),
                            _excel_value(http.get("redirect_chain")),
                            _excel_value(http.get("error")),
                        ]
                    )
            for finding in result.finding_observations or []:
                if not isinstance(finding, dict):
                    continue
                workbook["Findings"].append(
                    [
                        _excel_value(finding.get("severity")),
                        _excel_value(finding.get("category")),
                        _excel_value(finding.get("title")),
                        _excel_value(finding.get("status", "open")),
                        _excel_value(result.asset_id or result.hostname),
                        _excel_value(finding.get("last_seen_at") or result.finished_at),
                    ]
                )
            for port in result.port_observations or []:
                if isinstance(port, dict):
                    port_row = [
                        _excel_value(result.asset_id or result.hostname),
                        port.get("port"),
                        _excel_value(port.get("protocol")),
                        _excel_value(port.get("status")),
                        _excel_value(port.get("service_guess")),
                        _excel_value(port.get("banner")),
                        _excel_value(port.get("error")),
                    ]
                    workbook["Port Results"].append(port_row)
                    if port.get("status") == "open":
                        workbook["Open Ports"].append(port_row[:-1])
            for header in result.header_observations or []:
                if isinstance(header, dict):
                    workbook["Security Headers"].append(
                        [
                            _excel_value(result.asset_id or result.hostname),
                            _excel_value(header.get("header_name")),
                            header.get("present"),
                            _excel_value(header.get("value")),
                            _excel_value(header.get("risk_level")),
                            _excel_value(header.get("recommendation")),
                            _excel_value(header.get("url") or header.get("requested_url")),
                            _excel_value(header.get("rule_id")),
                            header.get("issue"),
                        ]
                    )
            for tls in result.tls_observations or []:
                if isinstance(tls, dict):
                    workbook["SSL TLS"].append(
                        [
                            _excel_value(result.asset_id or result.hostname),
                            tls.get("port", 443),
                            _excel_value(tls.get("issuer")),
                            _excel_value(tls.get("subject_common_name")),
                            _excel_value(tls.get("valid_until")),
                            tls.get("days_until_expiry"),
                            _excel_value(tls.get("status")),
                            _excel_value(tls.get("tls_version")),
                            _excel_value(tls.get("cipher")),
                            tls.get("certificate_verified"),
                            _excel_value(tls.get("error")),
                        ]
                    )
            for technology in result.technology_observations or []:
                if isinstance(technology, dict):
                    workbook["Technologies"].append(
                        [
                            _excel_value(result.asset_id or result.hostname),
                            _excel_value(technology.get("name")),
                            _excel_value(technology.get("category")),
                            technology.get("confidence"),
                            _excel_value(technology.get("evidence")),
                            _excel_value(technology.get("url") or technology.get("requested_url")),
                        ]
                    )
            for exposure in result.exposure_observations or []:
                if isinstance(exposure, dict):
                    workbook["Exposure Checks"].append(
                        [
                            _excel_value(result.asset_id or result.hostname),
                            _excel_value(exposure.get("requested_url")),
                            _excel_value(exposure.get("url")),
                            _excel_value(exposure.get("path")),
                            exposure.get("status_code"),
                            _excel_value(exposure.get("content_type")),
                            exposure.get("content_length"),
                            exposure.get("tls_verified"),
                            exposure.get("response_time_ms"),
                            _excel_value(exposure.get("redirect_chain")),
                            _excel_value(exposure.get("error")),
                        ]
                    )
    else:
        for asset in db.scalars(select(Asset).where(Asset.project_id == project.id, Asset.scan_id == scan.id).order_by(Asset.hostname.asc())):
            workbook["Assets"].append([_excel_value(asset.hostname), asset.asset_type, _excel_value(asset.ip_address), asset.status, "completed", asset.risk_level, _safe_text(asset.first_seen_at), _safe_text(asset.last_seen_at)])
        for finding in db.scalars(select(Finding).where(Finding.project_id == project.id, Finding.scan_id == scan.id).order_by(Finding.last_seen_at.desc())):
            workbook["Findings"].append([finding.severity, finding.category, _excel_value(finding.title), finding.status, finding.asset_id, _safe_text(finding.last_seen_at)])
        for port in db.scalars(select(Port).where(Port.project_id == project.id, Port.scan_id == scan.id).order_by(Port.port.asc())):
            port_row = [port.asset_id, port.port, port.protocol, port.status, port.service_guess, _excel_value(port.banner)]
            workbook["Port Results"].append([*port_row, ""])
            if port.status == "open":
                workbook["Open Ports"].append(port_row)
        for header in db.scalars(select(SecurityHeader).where(SecurityHeader.project_id == project.id, SecurityHeader.scan_id == scan.id).order_by(SecurityHeader.header_name.asc())):
            workbook["Security Headers"].append([header.asset_id, header.header_name, header.present, _excel_value(header.value), header.risk_level, _excel_value(header.recommendation), "", "", None])
        for ssl_result in db.scalars(select(SslResult).where(SslResult.project_id == project.id, SslResult.scan_id == scan.id)):
            workbook["SSL TLS"].append([ssl_result.asset_id, 443, _excel_value(ssl_result.issuer), _excel_value(ssl_result.subject_common_name), _safe_text(ssl_result.valid_until), ssl_result.days_until_expiry, ssl_result.status, _excel_value((ssl_result.tls_versions or [None])[0]), "", "", _excel_value(ssl_result.error)])
        for technology in db.scalars(select(Technology).where(Technology.project_id == project.id, Technology.scan_id == scan.id).order_by(Technology.name.asc())):
            workbook["Technologies"].append([technology.asset_id, _excel_value(technology.name), _excel_value(technology.category), technology.confidence, _excel_value(technology.evidence), ""])
    for change in db.scalars(select(Change).where(Change.project_id == project.id, Change.scan_id == scan.id).order_by(Change.detected_at.desc())):
        workbook["Changes"].append([change.asset_id, change.change_type, _excel_value(change.old_value), _excel_value(change.new_value), change.severity, _safe_text(change.detected_at)])
    workbook["Scan Metadata"].append(
        [
            scan.id,
            scan.status,
            _safe_text(scan.started_at),
            _safe_text(scan.finished_at),
            scan.attempt_count,
            _safe_text(scan.heartbeat_at),
            scan.assets_discovered,
            scan.assets_scanned,
            scan.assets_failed,
            scan.findings_created,
            scan.checks_completed,
            scan.checks_failed,
            scan.coverage_percent,
            scan.risk_score,
        ]
    )

    for sheet in workbook.worksheets:
        sheet.freeze_panes = "A2"
        sheet.auto_filter.ref = sheet.dimensions
        for column_cells in sheet.columns:
            width = min(60, max(12, max(len(_safe_text(cell.value)) for cell in column_cells) + 2))
            sheet.column_dimensions[column_cells[0].column_letter].width = width

    workbook.save(path)
    return path
