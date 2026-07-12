# Report Format

## PDF

- Cover page
- Project name and domain
- Selected scan profile and date
- Selected scan ID
- Executive summary
- Scan risk score
- Asset summary
- Findings summary by severity
- All findings in severity order
- Detailed findings with business impact, evidence, and recommendations
- Recommendations
- Complete target coverage appendix and scan metadata
- Authorized-use disclaimer

## Excel

Sheets:

- Summary
- Assets
- Findings
- Open Ports
- Port Results (including closed, filtered, unreachable, and error outcomes)
- HTTP Endpoints
- Security Headers
- SSL/TLS
- Technologies
- Exposure Checks
- Changes
- Target Diagnostics
- Scan Metadata

Every generated report is tied to one selected terminal scan through `reports.scan_id`. New reports read immutable target manifests, so later rescans cannot remove historical assets, findings, ports, headers, TLS observations, or technologies. Partial scans can be exported, but their coverage percentage and partial reason are displayed prominently. Spreadsheet cells are protected against formula injection and report downloads are restricted to the configured report directory.
