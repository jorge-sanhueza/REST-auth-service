export interface JwtUser {
  id: string;
  email: string;
  name: string;
  tenantId: string;
  role: string;
  permissions: string[];
}
