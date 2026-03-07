import { JwtUser } from '../dto/auth.dto';

declare module 'express' {
  interface Request {
    user?: JwtUser;
    tenantId?: string;
  }
}
