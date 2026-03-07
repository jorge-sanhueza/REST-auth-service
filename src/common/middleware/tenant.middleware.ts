import { JwtUser } from '@/auth/dto/auth.dto';
import { Injectable, NestMiddleware, ForbiddenException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

export interface TenantRequest extends Request {
  user?: JwtUser;
  tenantId?: string;
  body: {
    tenantId?: string;
    [key: string]: any;
  };
}

@Injectable()
export class TenantMiddleware implements NestMiddleware {
  use(req: TenantRequest, res: Response, next: NextFunction) {
    const { user } = req;

    if (!user) {
      throw new ForbiddenException(
        'Authentication required for tenant context',
      );
    }

    const requestedTenantId =
      (req.params.tenantId as string) ||
      (req.body?.tenantId as string) ||
      (req.query.tenantId as string) ||
      undefined;

    let effectiveTenantId: string;

    if (!requestedTenantId) {
      effectiveTenantId = user.tenantId;
    } else {
      if (
        requestedTenantId !== user.tenantId &&
        !user.permissions.includes('tenants:access:all')
      ) {
        throw new ForbiddenException(
          'Cannot access resources from other tenants',
        );
      }
      effectiveTenantId = requestedTenantId;
    }

    req.tenantId = effectiveTenantId;

    next();
  }
}
