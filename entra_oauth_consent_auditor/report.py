import csv
import json
import os
from typing import List, Dict
from datetime import datetime, timezone

def ensure_output_dir(path: str):
    if not os.path.exists(path):
        os.makedirs(path)

def write_csv(findings: List[Dict], output_dir: str, filename: str = "entra_oauth_consent_auditor.csv"):
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, filename)
    
    if not findings:
        # Create empty file with headers
        fieldnames = [
            "FindingType", "ClientDisplayName", "ClientAppId", "ClientSpId",
            "ResourceDisplayName", "ResourceAppId", "ResourceSpId",
            "PrincipalDisplayName", "PrincipalUPN", "PrincipalId",
            "ConsentType", "Scopes", "RiskyItems", "RiskyCount",
            "CreatedDateTime", "ExpiryTime"
        ]
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
        return filepath

    # Deterministic Sort
    # FindingType then ClientDisplayName then ResourceDisplayName then PrincipalUPN then Scopes
    findings.sort(key=lambda x: (
        x.get("FindingType", ""),
        x.get("ClientDisplayName", "") or "",
        x.get("ResourceDisplayName", "") or "",
        x.get("PrincipalUPN", "") or "",
        x.get("Scopes", "") or ""
    ))
    
    # Keys from the first finding or fixed list? Safe to use fixed list to ensure column order.
    fieldnames = [
        "FindingType", "ClientDisplayName", "ClientAppId", "ClientSpId",
        "ResourceDisplayName", "ResourceAppId", "ResourceSpId",
        "PrincipalDisplayName", "PrincipalUPN", "PrincipalId",
        "ConsentType", "Scopes", "RiskyItems", "RiskyCount",
        "RiskReason", "RiskNotes",
        "CreatedDateTime", "ExpiryTime", "ClientPublisher"
    ]
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            # Filter dict to only fieldnames to avoid errors if extra keys exist
            row = {k: finding.get(k, "") for k in fieldnames}
            writer.writerow(row)
            
    return filepath

def write_json(findings: List[Dict], tenant_id: str, output_dir: str, filename: str = "entra_oauth_consent_auditor.json", version: str = "Unknown"):
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, filename)
    
    # Calculate summary
    total_findings = len(findings)
    risky_findings = sum(1 for f in findings if f.get("RiskyCount", 0) > 0)
    
    # Distinguish types
    delegated = [f for f in findings if f.get("FindingType") == "DELEGATED_GRANT"]
    app_roles = [f for f in findings if f.get("FindingType") == "APP_ROLE_ASSIGNMENT"]
    
    summary = {
        "total_findings": total_findings,
        "risky_findings": risky_findings,
        "total_delegated_grants": len(delegated),
        "risky_delegated_grants": sum(1 for f in delegated if f.get("RiskyCount", 0) > 0),
        "total_app_role_assignments": len(app_roles),
        "risky_app_role_assignments": sum(1 for f in app_roles if f.get("RiskyCount", 0) > 0)
    }
    
    # Deterministic Sort (same as CSV)
    findings.sort(key=lambda x: (
        x.get("FindingType", ""),
        x.get("ClientDisplayName", "") or "",
        x.get("ResourceDisplayName", "") or "",
        x.get("PrincipalUPN", "") or "",
        x.get("Scopes", "") or ""
    ))

    output = {
        "metadata": {
            "toolName": "entra_oauth_consent_auditor",
            "toolVersion": version,
            "tenantId": tenant_id,
            "runTimestampUtc": datetime.now(timezone.utc).isoformat()
        },
        "summary": summary,
        "findings": findings
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
        
    return filepath
