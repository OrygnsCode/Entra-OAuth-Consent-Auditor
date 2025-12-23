import logging
from typing import List, Dict, Set, Optional
from .graph import GraphClient

logger = logging.getLogger(__name__)

# Default risky definitions
DEFAULT_RISKY_SCOPES = {
    "Directory.AccessAsUser.All",
    "Mail.Read", "Mail.ReadWrite",
    "Files.Read.All", "Files.ReadWrite.All",
    "Sites.Read.All", "Sites.ReadWrite.All",
    "offline_access",
    "User.Read.All", "Group.Read.All",
    "Policy.Read.All",
    "RoleManagement.ReadWrite.Directory",
}
# Also flag any scope with "ReadWrite"

DEFAULT_RISKY_ROLES = {
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
}

class EntityResolver:
    """
    Caches and resolves User and ServicePrincipal details to minimize API calls.
    """
    def __init__(self, client: GraphClient):
        self.client = client
        self.users: Dict[str, Dict] = {}
        self.service_principals: Dict[str, Dict] = {}
        
    def get_user(self, user_id: str) -> Optional[Dict]:
        if not user_id:
            return None
        if user_id in self.users:
            return self.users[user_id]
        
        try:
            # Select only needed fields
            user_data = self.client.get(f"/users/{user_id}?$select=id,displayName,userPrincipalName")
            self.users[user_id] = user_data
            return user_data
        except Exception as e:
            logger.warning(f"Could not resolve user {user_id}: {e}")
            self.users[user_id] = {"displayName": "Unknown", "userPrincipalName": "Unknown"}
            return self.users[user_id]

    def get_service_principal(self, sp_id: str) -> Optional[Dict]:
        if not sp_id:
            return None
        if sp_id in self.service_principals:
            return self.service_principals[sp_id]
        
        try:
            # Need displayName, appId, and verifiedPublisher
            # verifiedPublisher is a complex type
            sp_data = self.client.get(f"/servicePrincipals/{sp_id}?$select=id,appId,displayName,verifiedPublisher")
            self.service_principals[sp_id] = sp_data
            return sp_data
        except Exception as e:
            logger.warning(f"Could not resolve SP {sp_id}: {e}")
            self.service_principals[sp_id] = {"displayName": "Unknown", "appId": "Unknown"}
            return self.service_principals[sp_id]

class Auditor:
    def __init__(self, client: GraphClient, risky_scopes=None, risky_roles=None):
        self.client = client
        self.resolver = EntityResolver(client)
        self.risky_scopes = set(risky_scopes) if risky_scopes else DEFAULT_RISKY_SCOPES
        self.risky_roles = set(risky_roles) if risky_roles else DEFAULT_RISKY_ROLES
        self.graph_sp_id = None
        self.graph_app_roles = {} # ID -> Value (Name)

    def _is_scope_risky(self, scope: str) -> bool:
        if scope in self.risky_scopes:
            return True
        if "ReadWrite" in scope:
            return True
        return False

    def _is_role_risky(self, role_value: str) -> bool:
        if role_value in self.risky_roles:
            return True
        # For roles, user asked to flag Graph-related ones.
        return False

    def _get_graph_sp_details(self):
        """Finds the Microsoft Graph Service Principal and caches its app roles."""
        if self.graph_sp_id:
            return

        logger.info("Resolving Microsoft Graph Service Principal...")
        # AppId for Microsoft Graph is mostly constant: 00000003-0000-0000-c000-000000000000
        graph_app_id = "00000003-0000-0000-c000-000000000000"
        
        results = list(self.client.get_all(f"/servicePrincipals?$filter=appId eq '{graph_app_id}'"))
        if not results:
            logger.error("Could not find Microsoft Graph Service Principal!")
            return
        
        sp = results[0]
        self.graph_sp_id = sp['id']
        
        # Cache roles: id -> value
        for role in sp.get('appRoles', []):
            self.graph_app_roles[role['id']] = role.get('value')
        
        logger.info(f"Resolved Graph SP ID: {self.graph_sp_id}, found {len(self.graph_app_roles)} roles.")

    def audit_delegated_grants(self) -> List[Dict]:
        logger.info("Auditing Delegated Permission Grants...")
        findings = []
        
        # https://graph.microsoft.com/v1.0/oauth2PermissionGrants
        grants = self.client.get_all("/oauth2PermissionGrants")
        
        for g in grants:
            client_sp_id = g.get('clientId')
            resource_sp_id = g.get('resourceId')
            principal_id = g.get('principalId')
            scope_string = g.get('scope', '')
            
            # Resolve Client
            client_sp = self.resolver.get_service_principal(client_sp_id)
            client_display = client_sp.get('displayName', '')
            client_app_id = client_sp.get('appId', '')
            
            # Resolve Resource
            resource_sp = self.resolver.get_service_principal(resource_sp_id)
            resource_display = resource_sp.get('displayName', '')
            resource_app_id = resource_sp.get('appId', '')
            
            # Resolve Principal
            if principal_id:
                user = self.resolver.get_user(principal_id)
                principal_display = user.get('displayName', '')
                principal_upn = user.get('userPrincipalName', '')
            else:
                principal_display = "All Users"
                principal_upn = "Tenant-wide"
                principal_id = "" # Normalized empty string
                
            # Analyze Scopes
            scopes = scope_string.split(' ')
            risky_items = []
            for s in scopes:
                if s and self._is_scope_risky(s):
                    risky_items.append(s)
            
            findings.append({
                "FindingType": "DELEGATED_GRANT",
                "ClientDisplayName": client_display,
                "ClientAppId": client_app_id,
                "ClientSpId": client_sp_id,
                "ResourceDisplayName": resource_display,
                "ResourceAppId": resource_app_id,
                "ResourceSpId": resource_sp_id,
                "PrincipalDisplayName": principal_display,
                "PrincipalUPN": principal_upn,
                "PrincipalId": principal_id,
                "ConsentType": g.get('consentType'),
                "Scopes": scope_string,
                "RiskyItems": ",".join(sorted(risky_items)),
                "RiskyCount": len(risky_items),
                "CreatedDateTime": g.get('startTime'), # oauth2PermissionGrants uses startTime
                "ExpiryTime": g.get('expiryTime'),
            })
            
        return findings

    def audit_app_roles(self) -> List[Dict]:
        logger.info("Auditing App Role Assignments (Application Permissions)...")
        self._get_graph_sp_details()
        if not self.graph_sp_id:
            return []

        findings = []
        
        # Iterate all SPs to find their assignments TO Graph
        # Note: /servicePrincipals?$select=id,appId,displayName
        # We must iterate ALL SPs. This can be heavy.
        # Optimized way: None easily available without filtering on resourceId 
        # but appRoleAssignments doesn't support filtering on resourceId globally on v1.0 usually?
        # Actually: GET /servicePrincipals/{id}/appRoleAssignments
        # We have to loop.
        
        all_sps = self.client.get_all("/servicePrincipals?$select=id,appId,displayName")
        
        for sp in all_sps:
            sp_id = sp['id']
            sp_display = sp.get('displayName')
            sp_app_id = sp.get('appId')
            
            # Get assignments for this SP (as client)
            try:
                # Filter for Graph assignments only
                assignments = self.client.get_all(f"/servicePrincipals/{sp_id}/appRoleAssignments?$filter=resourceId eq '{self.graph_sp_id}'")
                
                for assign in assignments:
                    role_id = assign.get('appRoleId')
                    if role_id == "00000000-0000-0000-0000-000000000000":
                        # Default role, ignore
                        continue
                        
                    role_val = self.graph_app_roles.get(role_id, f"Unknown-Role-{role_id}")
                    
                    is_risky = self._is_role_risky(role_val)
                    risky_items = [role_val] if is_risky else []
                    
                    findings.append({
                        "FindingType": "APP_ROLE_ASSIGNMENT",
                        "ClientDisplayName": sp_display,
                        "ClientAppId": sp_app_id,
                        "ClientSpId": sp_id,
                        "ResourceDisplayName": "Microsoft Graph", # Fixed since we filtered
                        "ResourceAppId": "00000003-0000-0000-c000-000000000000",
                        "ResourceSpId": self.graph_sp_id,
                        "PrincipalDisplayName": "", # N/A for app-only
                        "PrincipalUPN": "", # N/A
                        "PrincipalId": "", # N/A
                        "ConsentType": "Application",
                        "Scopes": role_val, # Use Scopes col for the role name
                        "RiskyItems": ",".join(risky_items),
                        "RiskyCount": len(risky_items),
                        "CreatedDateTime": assign.get('createdDateTime'),
                        "ExpiryTime": "", # Usually null for app roles
                    })

            except Exception as e:
                logger.error(f"Error checking assignments for SP {sp_display} ({sp_id}): {e}")
                
        return findings
