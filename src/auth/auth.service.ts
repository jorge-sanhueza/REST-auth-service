import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RedisEventService } from '../events/redis-event.service';
import { RateLimiterService } from './rate-limiter.service';
import * as bcrypt from 'bcrypt';
import { User, Role } from '@prisma/client';
import {
  LoginDto,
  RegisterDto,
  RefreshTokenDto,
  AuthResponseDto,
} from './dto/auth.dto';
import { JwtUser } from './interfaces/auth.interface';
import { createHash } from 'crypto';

/** Produces a SHA-256 hex digest of a refresh token for safe DB storage. */
function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Safely casts the Prisma Json permissions field to a typed string array. */
function toPermissions(value: unknown): string[] {
  return Array.isArray(value) ? (value as string[]) : [];
}

type UserWithRole = User & { role: Role };

interface AuthEventPayload {
  userId: string;
  email: string;
  tenantId: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

// Access tokens expire in 15 minutes — blacklist entries must outlive them.
const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly refreshSecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly eventService: RedisEventService,
    private readonly configService: ConfigService,
    private readonly rateLimiter: RateLimiterService,
  ) {
    this.refreshSecret =
      this.configService.getOrThrow<string>('REFRESH_SECRET');
  }

  async login(
    loginDto: LoginDto,
    metadata?: { ip?: string; userAgent?: string },
  ): Promise<AuthResponseDto> {
    const { email, password, tenantId } = loginDto;
    const key = `${email}:${tenantId}`;

    await this.checkRateLimit(key);

    const user = await this.prisma.user.findFirst({
      where: { email, tenantId: tenantId ?? undefined, isActive: true },
      include: { role: true },
    });

    const isValid = user && (await bcrypt.compare(password, user.passwordHash));

    if (!isValid) {
      await this.handleFailedLogin(key, user ?? undefined);
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.rateLimiter.resetLoginAttempts(key);

    const { accessToken, refreshToken } = this.generateTokens(user);

    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: user.id },
        data: {
          refreshToken: hashToken(refreshToken),
          tokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          lastLoginAt: new Date(),
        },
      }),
      this.prisma.auditLog.create({
        data: {
          userId: user.id,
          userEmail: user.email,
          tenantId: user.tenantId,
          action: 'LOGIN_SUCCESS',
          status: 'SUCCESS',
          ipAddress: metadata?.ip,
          userAgent: metadata?.userAgent,
        },
      }),
    ]);

    await this.eventService.emit<AuthEventPayload>('auth.login.success', {
      userId: user.id,
      email: user.email,
      tenantId: user.tenantId,
      timestamp: new Date(),
      metadata: { ip: metadata?.ip },
    });

    this.logger.log(`User logged in: ${user.email} (${user.tenantId})`);

    return this.mapToAuthResponse(user, accessToken, refreshToken);
  }

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const { email, name, password, rut, phone, tenantId, roleId } = registerDto;

    this.validatePasswordStrength(password);

    const existingUser = await this.prisma.user.findFirst({
      where: { email, tenantId },
    });

    if (existingUser) {
      throw new BadRequestException('User already exists in this tenant');
    }

    const finalRole = roleId
      ? await this.prisma.role.findFirst({ where: { id: roleId } })
      : await this.prisma.role.findFirst({ where: { tenantId, name: 'User' } });

    if (!finalRole) {
      throw new BadRequestException(
        roleId
          ? 'Provided roleId does not exist'
          : 'No default role found for tenant',
      );
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const tokenExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    // Create the user first to get id, write refresh token in the same transaction.
    // Both tokens are generated once from the same jti so the access token returned to the client is consistent.
    const { user, accessToken, refreshToken } = await this.prisma.$transaction(
      async (tx) => {
        const created = await tx.user.create({
          data: {
            email,
            name,
            passwordHash,
            rut,
            phone,
            tenantId,
            roleId: finalRole.id,
          },
          include: { role: true },
        });

        const tokens = this.generateTokens(created);

        const updated = await tx.user.update({
          where: { id: created.id },
          data: { refreshToken: hashToken(tokens.refreshToken), tokenExpiry },
          include: { role: true },
        });

        return { user: updated, ...tokens };
      },
    );

    await this.eventService.emit('user.created', {
      userId: user.id,
      email: user.email,
      name: user.name,
      tenantId: user.tenantId,
      role: user.role.name,
      permissions: user.role.permissions,
      timestamp: new Date(),
    });

    this.logger.log(`New user registered: ${user.email}`);

    return this.mapToAuthResponse(user, accessToken, refreshToken);
  }

  async refreshToken(dto: RefreshTokenDto): Promise<{ accessToken: string }> {
    try {
      const payload = this.jwtService.verify<{ sub: string }>(
        dto.refreshToken,
        { secret: this.refreshSecret, algorithms: ['HS256'] },
      );

      const user = await this.prisma.user.findFirst({
        where: {
          id: payload.sub,
          refreshToken: hashToken(dto.refreshToken),
          tokenExpiry: { gt: new Date() },
          isActive: true,
        },
        include: { role: true },
      });

      if (!user) {
        throw new UnauthorizedException();
      }

      const { accessToken } = this.generateTokens(user);
      return { accessToken };
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  } //consider adding token rotation

  async logout(userId: string, token?: string): Promise<void> {
    if (token) {
      await this.rateLimiter.blacklistToken(token, ACCESS_TOKEN_TTL_SECONDS);
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: null,
        tokenExpiry: null,
      },
    });

    await this.eventService.emit('user.logout', {
      userId,
      timestamp: new Date(),
    });

    this.logger.log(`User logged out: ${userId}`);
  }

  async revokeAllSessions(userId: string, exceptToken?: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: exceptToken ? hashToken(exceptToken) : null,
        tokenExpiry: exceptToken
          ? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
          : null,
      },
    });

    await this.eventService.emit('user.sessions.revoked', {
      userId,
      exceptToken,
      timestamp: new Date(),
    });
  }

  async isTokenBlacklisted(token: string): Promise<boolean> {
    return this.rateLimiter.isTokenBlacklisted(token);
  }

  async validateUser(userId: string): Promise<JwtUser | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId, isActive: true },
        include: { role: true, tenant: true },
      });

      if (!user) {
        this.logger.debug(
          `User validation failed: User ${userId} not found or inactive`,
        );
        return null;
      }

      return {
        id: user.id,
        email: user.email,
        name: user.name,
        tenantId: user.tenantId,
        role: user.role.name,
        permissions: toPermissions(user.role.permissions),
      };
    } catch (error) {
      this.logger.error(`Error validating user ${userId}:`, error);
      return null;
    }
  }

  private generateTokens(user: UserWithRole): {
    accessToken: string;
    refreshToken: string;
  } {
    const payload = {
      sub: user.id,
      email: user.email,
      tenantId: user.tenantId,
      role: user.role.name,
      permissions: user.role.permissions,
      jti: crypto.randomUUID(),
    };

    return {
      accessToken: this.jwtService.sign(payload),
      refreshToken: this.jwtService.sign(
        { sub: user.id },
        { expiresIn: '7d', secret: this.refreshSecret },
      ),
    };
  }

  private async checkRateLimit(key: string): Promise<void> {
    try {
      await this.rateLimiter.consumeLoginAttempt(key);
    } catch {
      throw new UnauthorizedException(
        'Too many failed attempts. Try again later.',
      );
    }
  }

  private async handleFailedLogin(
    key: string,
    user?: UserWithRole,
  ): Promise<void> {
    // The next login attempt will consume another point.
    // We only need to emit events here.
    if (user) {
      await this.eventService.emit<AuthEventPayload>('auth.login.failed', {
        userId: user.id,
        email: user.email,
        tenantId: user.tenantId,
        timestamp: new Date(),
      });

      await this.prisma.auditLog.create({
        data: {
          userId: user.id,
          userEmail: user.email,
          tenantId: user.tenantId,
          action: 'LOGIN_FAILED',
          status: 'FAILURE',
        },
      });
    }
  }

  private validatePasswordStrength(password: string): void {
    const requirements = [
      {
        test: password.length >= 6,
        message: 'Password must be at least 6 characters',
      },
      {
        test: /[A-Z]/.test(password),
        message: 'Password must contain uppercase letter',
      },
      {
        test: /[a-z]/.test(password),
        message: 'Password must contain lowercase letter',
      },
      { test: /[0-9]/.test(password), message: 'Password must contain number' },
      {
        test: /[^A-Za-z0-9]/.test(password),
        message: 'Password must contain special character',
      },
    ];

    const failed = requirements.filter((r) => !r.test);
    if (failed.length) {
      throw new BadRequestException(failed.map((f) => f.message));
    }
  }

  private mapToAuthResponse(
    user: UserWithRole,
    accessToken: string,
    refreshToken: string,
  ): AuthResponseDto {
    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        tenantId: user.tenantId,
        role: user.role.name,
        permissions: toPermissions(user.role.permissions),
      },
    };
  }
}
