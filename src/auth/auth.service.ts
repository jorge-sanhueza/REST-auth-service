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
import * as bcrypt from 'bcrypt';
import { Prisma, User, Role } from '@prisma/client';
import {
  LoginDto,
  RegisterDto,
  RefreshTokenDto,
  AuthResponseDto,
} from './dto/auth.dto';

type UserWithRole = User & { role: Role };

interface AuthEventPayload {
  userId: string;
  email: string;
  tenantId: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly refreshSecret: string;
  private readonly loginAttempts = new Map<
    string,
    { count: number; firstAttempt: Date }
  >();
  private readonly tokenBlacklist = new Set<string>();

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private eventService: RedisEventService,
    private configService: ConfigService,
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

    // Rate limiting
    this.checkRateLimit(key);

    const user = await this.prisma.user.findFirst({
      where: { email, tenantId: tenantId ?? undefined, isActive: true },
      include: { role: true },
    });

    const isValid = user && (await bcrypt.compare(password, user.passwordHash));

    if (!isValid) {
      await this.handleFailedLogin(key, user ?? undefined);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Clear rate limiting on success
    this.loginAttempts.delete(key);

    const { accessToken, refreshToken } = this.generateTokens(user);

    // Atomic update with session tracking
    await this.prisma.$transaction([
      this.prisma.user.update({
        where: { id: user.id },
        data: {
          refreshToken,
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
          details: {
            ip: metadata?.ip,
            userAgent: metadata?.userAgent,
            timestamp: new Date().toISOString(),
          } as Prisma.InputJsonValue,
        },
      }),
    ]);

    // Emit success event
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

    // Validate password strength
    this.validatePasswordStrength(password);

    // Check existing user
    const existingUser = await this.prisma.user.findFirst({
      where: { email, tenantId },
    });

    if (existingUser) {
      throw new BadRequestException('User already exists in this tenant');
    }

    // Get default role if not provided
    let finalRoleId = roleId;
    if (!finalRoleId) {
      const defaultRole = await this.prisma.role.findFirst({
        where: { tenantId, name: 'User' },
      });

      if (!defaultRole) {
        throw new BadRequestException('No default role found for tenant');
      }
      finalRoleId = defaultRole.id;
    }

    // Hash password and create user
    const passwordHash = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        email,
        name,
        passwordHash,
        rut,
        phone,
        tenantId,
        roleId: finalRoleId,
      },
      include: { role: true },
    });

    const { accessToken, refreshToken } = this.generateTokens(user);

    // Update with refresh token
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        refreshToken,
        tokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    // Emit event
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
        {
          secret: this.refreshSecret,
        },
      );

      const user = await this.prisma.user.findFirst({
        where: {
          id: payload.sub,
          refreshToken: dto.refreshToken,
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
  }

  async logout(userId: string, token?: string): Promise<void> {
    if (token) {
      // Blacklist the token
      this.tokenBlacklist.add(token);
      // Auto-expire after 15 minutes
      setTimeout(() => this.tokenBlacklist.delete(token), 15 * 60 * 1000);
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
        refreshToken: exceptToken || null,
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

  isTokenBlacklisted(token: string): boolean {
    return this.tokenBlacklist.has(token);
  }

  private generateTokens(user: UserWithRole) {
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

  private checkRateLimit(key: string): void {
    const attempts = this.loginAttempts.get(key) || {
      count: 0,
      firstAttempt: new Date(),
    };

    // Reset after 15 minutes
    if (Date.now() - attempts.firstAttempt.getTime() > 15 * 60 * 1000) {
      attempts.count = 0;
      attempts.firstAttempt = new Date();
    }

    if (attempts.count >= 5) {
      throw new UnauthorizedException(
        'Too many failed attempts. Try again later.',
      );
    }
  }

  private async handleFailedLogin(
    key: string,
    user?: UserWithRole,
  ): Promise<void> {
    const attempts = this.loginAttempts.get(key) || {
      count: 0,
      firstAttempt: new Date(),
    };
    attempts.count++;
    this.loginAttempts.set(key, attempts);

    if (user) {
      await this.eventService.emit<AuthEventPayload>('auth.login.failed', {
        userId: user.id,
        email: user.email,
        tenantId: user.tenantId,
        timestamp: new Date(),
        metadata: { attemptCount: attempts.count },
      });

      await this.prisma.auditLog.create({
        data: {
          userId: user.id,
          userEmail: user.email,
          tenantId: user.tenantId,
          action: 'LOGIN_FAILED',
          status: 'FAILURE',
          details: { attemptCount: attempts.count } as Prisma.InputJsonValue,
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

  async validateUser(userId: string): Promise<{
    id: string;
    email: string;
    name: string;
    tenantId: string;
    role: string;
    permissions: string[];
  } | null> {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          id: userId,
          isActive: true,
        },
        include: {
          role: true,
          tenant: true,
        },
      });

      if (!user) {
        this.logger.debug(
          `User validation failed: User ${userId} not found or inactive`,
        );
        return null;
      }

      // Return safe user object (no password hash, etc.)
      return {
        id: user.id,
        email: user.email,
        name: user.name,
        tenantId: user.tenantId,
        role: user.role.name,
        permissions: user.role.permissions as string[],
      };
    } catch (error) {
      this.logger.error(`Error validating user ${userId}:`, error);
      return null;
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
        permissions: user.role.permissions as string[],
      },
    };
  }
}
