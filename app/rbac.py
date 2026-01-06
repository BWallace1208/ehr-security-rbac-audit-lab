ROLE_PERMISSIONS = {
    "physician": {"patient:read"},
    "nurse": {"patient:read"},
    "billing": set(),          # billing should NOT read clinical notes in this simple model
    "it_admin": set(),         # IT admin shouldn’t read PHI; they administer systems, not charts
}

def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())
