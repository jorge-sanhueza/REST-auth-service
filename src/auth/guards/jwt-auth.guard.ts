import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JwtUser } from '../dto/auth.dto';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  handleRequest<T = JwtUser>(err: unknown, user: T | false): T {
    if (err || !user) {
      throw new UnauthorizedException('Authentication required');
    }

    return user;
  }
}
