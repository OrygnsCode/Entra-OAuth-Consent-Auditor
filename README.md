# Entra OAuth Consent Auditor

A read-only, deterministic CLI tool to audit OAuth consents (delegated grants) and risky Microsoft Graph application permissions (app roles) in Microsoft Entra ID.

**Security:** This tool is designed to be safe to ship. It does not write to the cloud, does not store secrets (uses `.env`), and produces clean CSV/JSON reports.

## Features

- **Audit Delegated Grants:** Lists all OAuth2 permission grants, resolving users, clients, and resources.
- **Audit App Roles:** Identifies Service Principals with risky assignments to Microsoft Graph (Optimized: audits assignments *to* Graph rather than iterating all SPs).
- **Risk Scoring:** Automatically flags risky permissions (e.g., `ReadWrite`, `Directory.AccessAsUser.All`). Includes `RiskReason` and `RiskNotes`.
- **Resilient:** Retries on 429 (Throttling) and 5xx (Server Errors).
- **Deterministic:** Outputs sorted, stable CSV and JSON files for diffability.
- **Safe:** Read-only operations.

## Setup

1. **Prerequisites:** Python 3.9+
2. **Clone** the repository.
3. **Install** dependencies: [pip install .]
   ```bash
   pip install -e .
   ```
4. **Environment Variables:**
   Copy `.env.example` to `.env` and fill in:
   ```bash
   TENANT_ID=your-tenant-id
   CLIENT_ID=your-app-client-id
   CLIENT_SECRET=your-app-client-secret
   ```
   *Note: Never commit `.env` to source control.*

### Required Permissions

The App Registration requires the following **Application Permissions** (granted via Admin Consent):

- `DelegatedPermissionGrant.ReadWrite.All` (or `Directory.Read.All` / `DelegatedPermissionGrant.Read.All`)
- `AppRoleAssignment.Read.All` (to read app role assignments)
- `Directory.Read.All` (to resolve Display Names)

## Usage

Run via CLI:

```bash
# Show help
entra-oauth-consent-auditor --help

# Audit and save to default out/ directory
entra-oauth-consent-auditor

# Exclude specific audit types
entra-oauth-consent-auditor --no-app-roles
entra-oauth-consent-auditor --no-delegated

# Audit only risky findings and fail if any found
entra-oauth-consent-auditor --only-risky --fail-on-risk

# Custom output directory
entra-oauth-consent-auditor --output-dir ./audit_reports
```

## Output Schema

Reports are generated in the `out/` directory (by default).

- **`entra_oauth_consent_auditor.csv`**: Flat file.
- **`entra_oauth_consent_auditor.json`**: Structured file with metadata and summary.

### CSV Columns
- `FindingType`: `DELEGATED_GRANT` or `APP_ROLE_ASSIGNMENT`
- `ClientDisplayName`, `ClientAppId`: The app initiating the access.
- `ClientPublisher`: Verified publisher of the client app.
- `ResourceDisplayName`: The API being accessed (e.g., Microsoft Graph).
- `PrincipalDisplayName`, `PrincipalUPN`: The user (delegated) or empty (app-only).
- `Scopes`: The permissions granted.
- `RiskyItems`: Subset of scopes deemed risky.
- `RiskyCount`: Number of risky items.
- `RiskReason`: Why this was flagged (e.g., `TenantWideConsent`, `RiskyGraphAppRole`).
- `RiskNotes`: Details on the risk.
- `ConsentType`: `Principal` (User) or `AllPrincipals` (Admin).

## Customizing Risk Rules

You can override the default risky scopes and roles by providing JSON files:

```bash
entra-oauth-consent-auditor --risk-scopes-json my_scopes.json --risk-roles-json my_roles.json
```

Format of JSON: `["Scope1", "Scope2", ...]`
