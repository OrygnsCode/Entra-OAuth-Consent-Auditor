# Entra OAuth Consent Auditor

A read-only, deterministic CLI tool to audit OAuth consents (delegated grants) and risky Microsoft Graph application permissions (app roles) in Microsoft Entra ID.

**Security:** This tool is designed to be safe to ship. It does not write to the cloud, does not store secrets (uses `.env`), and produces clean CSV/JSON reports.

## Features

- **Audit Delegated Grants:** Lists all OAuth2 permission grants, resolving users, clients, and resources.
- **Audit App Roles:** Identifies Service Principals with risky assignments to Microsoft Graph.
- **Risk Scoring:** automatically flags risky permissions (e.g., `ReadWrite`, `Directory.AccessAsUser.All`, etc.).
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

- `DelegatedPermissionGrant.ReadWrite.All` (for auditing grants - Read-Only would be ideal but Graph usually requires ReadWrite for full enumeration on this endpoint, though `DelegatedPermissionGrant.Read.All` is preferred if available/sufficient. The tool ONLY uses GET.)
  - *Correction:* `Directory.Read.All` is often sufficient for reading grants in some contexts, but `DelegatedPermissionGrant.Read.All` is specific.
- `AppRoleAssignment.Read.All` (to read app role assignments)
- `Directory.Read.All` (to resolve Display Names of users and service principals)

**Recommended Minimum Set:**
- `directory.read.all`
- `delegatedpermissiongrant.read.all`
- `approleassignment.read.all`

## Usage

Run via CLI:

```bash
# Show help
entra-oauth-consent-auditor --help

# Audit and save to default out/ directory
entra-oauth-consent-auditor

# Audit only risky findings and fail if any found (for CI/CD)
entra-oauth-consent-auditor --only-risky --fail-on-risk

# Custom output directory
entra-oauth-consent-auditor --output-dir ./audit_reports

# Run quietly (no stdout, just result code)
entra-oauth-consent-auditor --quiet
```

## Output Schema

Reports are generated in the `out/` directory (by default).

- **`entra_oauth_consent_auditor.csv`**: Flat file suitable for Excel/Splunk.
- **`entra_oauth_consent_auditor.json`**: Structured file with metadata and summary counts.

### CSV Columns
- `FindingType`: `DELEGATED_GRANT` or `APP_ROLE_ASSIGNMENT`
- `ClientDisplayName`, `ClientAppId`: The app initiating the access.
- `ResourceDisplayName`: The API being accessed (e.g., Microsoft Graph).
- `PrincipalDisplayName`, `PrincipalUPN`: The user (delegated) or empty (app-only).
- `Scopes`: The permissions granted.
- `RiskyItems`: Subset of scopes deemed risky.
- `RiskyCount`: Number of risky items.
- `ConsentType`: `Principal` (User) or `AllPrincipals` (Admin).

## Customizing Risk Rules

You can override the default risky scopes and roles by providing JSON files:

```bash
entra-oauth-consent-auditor --risk-scopes-json my_scopes.json --risk-roles-json my_roles.json
```

Format of JSON: `["Scope1", "Scope2", ...]`
