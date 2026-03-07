# Auth & Tenant Service

### Includes:

- **Core Authentication**: JWT-based auth with refresh tokens
- **Multi-tenancy**: Complete tenant isolation via middleware
- **RBAC**: Role-based access control with granular permissions
- **Event-Driven**: Redis event bus for service communication
- **Database**: Prisma ORM with PostgreSQL
- **Containerization**: Multi-stage Docker build
- **Orchestration**: Kubernetes deployment with health probes
- **Availability**: 2+ replicas with auto-scaling ready

### Service Details:

- **Internal DNS**: `auth-service.auth-system.svc.cluster.local:3000`
- **NodePort**: `30080`
- **Health Endpoint**: `/health`
- **API Base**: `/auth`

## Endpoints

| Method | Endpoint              | Description                  |
|--------|-----------------------|------------------------------|
| POST   | `/auth/login`         | User login                   |
| POST   | `/auth/register`      | New user registration        |
| POST   | `/auth/refresh`       | Refresh access token         |
| POST   | `/auth/logout`        | User logout                  |
| GET    | `/auth/profile`       | Get current user             |
| GET    | `/auth/tenant-info`   | Get tenant context           |
| DELETE | `/auth/sessions`      | Revoke all sessions          |
