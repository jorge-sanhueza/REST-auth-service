export const PERMISSIONS = {
  users: [
    '*',
    'create',
    'read',
    'update',
    'delete',
    'manage',
    'view:all',
    'view:own',
  ],
  roles: ['*', 'create', 'read', 'update', 'delete', 'manage'],
  orders: [
    '*',
    'create',
    'view:all',
    'view:assigned',
    'update:status',
    'assign',
    'delete',
  ],
  drivers: ['*', 'view', 'manage'],
  reports: ['*', 'generate', 'export'],
  settings: ['*', 'manage', 'view'],
  profile: ['*', 'edit', 'view'],
  tenants: ['*', 'read', 'update', 'manage'],
  audit: ['*', 'read', 'export'],
  system: ['*', 'configure', 'monitor'],
} as const;

// Type for the permissions object
export type PermissionResource = keyof typeof PERMISSIONS;
export type PermissionAction = (typeof PERMISSIONS)[PermissionResource][number];

// Helper to get all formatted permissions
export const getAllPermissions = (): Record<string, string[]> => {
  return Object.entries(PERMISSIONS).reduce(
    (acc, [resource, actions]) => {
      acc[resource] = actions.map((action) =>
        action === '*' ? `${resource}:*` : `${resource}:${action}`,
      );
      return acc;
    },
    {} as Record<string, string[]>,
  );
};

// Flatten all permissions into a single array (useful for validation)
export const getAllPermissionsFlat = (): string[] => {
  return Object.entries(PERMISSIONS).flatMap(([resource, actions]) =>
    actions.map((action) =>
      action === '*' ? `${resource}:*` : `${resource}:${action}`,
    ),
  );
};

// Only the essential system roles that every tenant needs
export const SYSTEM_ROLES = {
  ADMIN: {
    name: 'Admin',
    description: 'Tenant administrator with full access',
    permissions: ['*'], // Global wildcard
    isSystem: true,
  },
  USER: {
    name: 'User',
    description: 'Standard user with basic access',
    permissions: ['profile:*', 'orders:view:assigned', 'orders:update:status'],
    isSystem: true,
  },
} as const;
