/* eslint-disable @typescript-eslint/no-unsafe-assignment */

// Must be called before any imports so Jest replaces the module at the
// loader level. This avoids "Cannot redefine property" on bcrypt's
// non-configurable ES module exports.
jest.mock('bcrypt');

import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException, BadRequestException } from '@nestjs/common';
import { Prisma, Role, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { createHash } from 'crypto';

import { AuthService } from './auth.service';
import { PrismaService } from '../prisma/prisma.service';
import { RedisEventService } from '../events/redis-event.service';
import { RateLimiterService } from './rate-limiter.service';
import {
  AuthResponseDto,
  LoginDto,
  RefreshTokenDto,
  RegisterDto,
  UserDetailsDto,
} from './dto/auth.dto';
import { JwtUser } from './interfaces/auth.interface';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Mirror of the service-private hashToken so assertions stay honest. */
function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const mockRole: Role = {
  id: 'role-1',
  name: 'User',
  description: null,
  permissions: ['read:profile'] as unknown as Prisma.JsonValue,
  tenantId: 'tenant-1',
  isSystem: false,
  isActive: true,
  createdAt: new Date('2024-01-01'),
  updatedAt: new Date('2024-01-01'),
};

const mockUser: User & { role: Role } = {
  id: 'user-1',
  email: 'test@example.com',
  name: 'Test User',
  passwordHash: 'hashed-password',
  tenantId: 'tenant-1',
  roleId: 'role-1',
  role: mockRole,
  refreshToken: hashToken('existing-refresh-token'),
  tokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  isActive: true,
  lastLoginAt: new Date(),
  rut: '12345678-9',
  phone: '+56912345678',
  createdAt: new Date('2024-01-01'),
  updatedAt: new Date('2024-01-01'),
};

const mockUserDetails: UserDetailsDto = {
  id: mockUser.id,
  email: mockUser.email,
  name: mockUser.name,
  tenantId: mockUser.tenantId,
  role: mockRole.name,
  permissions: ['read:profile'],
};

// ─── Mock types ───────────────────────────────────────────────────────────────
//
// We define explicit mock delegate types rather than using jest.Mocked<PrismaService>
// for two reasons:
//
// 1. Prisma generates heavily overloaded call signatures per-method. TypeScript
//    cannot resolve a union of argument shapes against those overloads, producing
//    the "not assignable to parameter of type" errors seen with jest.Mocked<>.
//
// 2. NestJS service types like RedisEventService.emit use generic signatures that
//    jest.Mocked<> infers as returning `Promise<string>`, making
//    mockResolvedValue(undefined) fail. Explicit types let us declare the exact
//    return we need.
//
// Each mock method uses `(...args: unknown[])` for its parameters — we don't
// care about argument types on the mock itself; we assert on .toHaveBeenCalledWith
// separately where the exact shape matters.

type MockUserDelegate = {
  findFirst: jest.MockedFunction<
    (...args: unknown[]) => Promise<(User & { role: Role }) | null>
  >;
  findUnique: jest.MockedFunction<
    (
      ...args: unknown[]
    ) => Promise<(User & { role: Role; tenant: object }) | null>
  >;
  create: jest.MockedFunction<
    (...args: unknown[]) => Promise<User & { role: Role }>
  >;
  update: jest.MockedFunction<
    (...args: unknown[]) => Promise<User & { role: Role }>
  >;
};

type MockRoleDelegate = {
  findFirst: jest.MockedFunction<(...args: unknown[]) => Promise<Role | null>>;
};

type MockAuditLogDelegate = {
  create: jest.MockedFunction<(...args: unknown[]) => Promise<object>>;
};

type MockPrisma = {
  user: MockUserDelegate;
  role: MockRoleDelegate;
  auditLog: MockAuditLogDelegate;
  $transaction: jest.MockedFunction<(...args: unknown[]) => Promise<unknown>>;
};

type MockJwtService = {
  sign: jest.MockedFunction<(...args: unknown[]) => string>;
  verify: jest.MockedFunction<(...args: unknown[]) => object>;
};

type MockEventService = {
  emit: jest.MockedFunction<(...args: unknown[]) => Promise<void>>;
};

type MockConfigService = {
  getOrThrow: jest.MockedFunction<(...args: unknown[]) => string>;
};

type MockRateLimiter = {
  consumeLoginAttempt: jest.MockedFunction<(key: string) => Promise<void>>;
  resetLoginAttempts: jest.MockedFunction<(key: string) => Promise<void>>;
  blacklistToken: jest.MockedFunction<
    (token: string, ttl: number) => Promise<void>
  >;
  isTokenBlacklisted: jest.MockedFunction<(token: string) => Promise<boolean>>;
  onModuleDestroy: jest.MockedFunction<() => void>;
};

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('AuthService', () => {
  let service: AuthService;
  let prisma: MockPrisma;
  let jwt: MockJwtService;
  let events: MockEventService;
  let rateLimiter: MockRateLimiter;

  beforeEach(async () => {
    prisma = {
      user: {
        findFirst: jest.fn(),
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      role: {
        findFirst: jest.fn(),
      },
      auditLog: {
        create: jest.fn(),
      },
      $transaction: jest.fn(),
    };

    jwt = {
      sign: jest.fn().mockReturnValue('mock-token'),
      verify: jest.fn(),
    };

    events = {
      emit: jest.fn().mockResolvedValue(undefined),
    };

    const config: MockConfigService = {
      getOrThrow: jest.fn().mockReturnValue('test-refresh-secret'),
    };

    rateLimiter = {
      consumeLoginAttempt: jest.fn().mockResolvedValue(undefined),
      resetLoginAttempts: jest.fn().mockResolvedValue(undefined),
      blacklistToken: jest.fn().mockResolvedValue(undefined),
      isTokenBlacklisted: jest.fn().mockResolvedValue(false),
      onModuleDestroy: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prisma },
        { provide: JwtService, useValue: jwt },
        { provide: RedisEventService, useValue: events },
        { provide: ConfigService, useValue: config },
        { provide: RateLimiterService, useValue: rateLimiter },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ── login ──────────────────────────────────────────────────────────────────

  describe('login', () => {
    const loginDto: LoginDto = {
      email: 'test@example.com',
      password: 'Password1!',
      tenantId: 'tenant-1',
    };

    beforeEach(() => {
      prisma.user.findFirst.mockResolvedValue(mockUser);
      prisma.$transaction.mockResolvedValue([mockUser, {}]);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    });

    it('should return auth response on valid credentials', async () => {
      const expected: AuthResponseDto = {
        accessToken: 'mock-token',
        refreshToken: 'mock-token',
        user: mockUserDetails,
      };

      const result = await service.login(loginDto);

      expect(result).toEqual(expected);
    });

    it('should consume a rate-limit point on each attempt', async () => {
      await service.login(loginDto);

      expect(rateLimiter.consumeLoginAttempt).toHaveBeenCalledWith(
        `${loginDto.email}:${loginDto.tenantId}`,
      );
    });

    it('should reset rate-limit counter on successful login', async () => {
      await service.login(loginDto);

      expect(rateLimiter.resetLoginAttempts).toHaveBeenCalledWith(
        `${loginDto.email}:${loginDto.tenantId}`,
      );
    });

    it('should call prisma.$transaction with user update and audit log', async () => {
      await service.login(loginDto);

      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    });

    it('should store a hashed refresh token, not the raw token', async () => {
      await service.login(loginDto);

      expect(prisma.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            refreshToken: hashToken('mock-token'),
          }),
        }),
      );
    });

    it('should write ipAddress and userAgent to the audit log as dedicated columns', async () => {
      await service.login(loginDto, { ip: '127.0.0.1', userAgent: 'jest' });

      expect(prisma.auditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            ipAddress: '127.0.0.1',
            userAgent: 'jest',
          }),
        }),
      );
    });

    it('should emit auth.login.success event with ip metadata', async () => {
      await service.login(loginDto, { ip: '127.0.0.1' });

      expect(events.emit).toHaveBeenCalledWith(
        'auth.login.success',
        expect.objectContaining({
          userId: mockUser.id,
          email: mockUser.email,
          tenantId: mockUser.tenantId,
          metadata: { ip: '127.0.0.1' },
        }),
      );
    });

    it('should throw UnauthorizedException when user is not found', async () => {
      prisma.user.findFirst.mockResolvedValue(null);

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when password is invalid', async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.login(loginDto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should emit auth.login.failed event when a known user fails', async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.login(loginDto)).rejects.toThrow();

      expect(events.emit).toHaveBeenCalledWith(
        'auth.login.failed',
        expect.objectContaining({ userId: mockUser.id }),
      );
    });

    it('should throw UnauthorizedException when rate limiter rejects the attempt', async () => {
      rateLimiter.consumeLoginAttempt.mockRejectedValueOnce(
        new Error('Rate limit exceeded'),
      );

      await expect(service.login(loginDto)).rejects.toThrow(
        'Too many failed attempts. Try again later.',
      );
    });

    it('should not reach prisma or emit events when rate-limited', async () => {
      rateLimiter.consumeLoginAttempt.mockRejectedValueOnce(
        new Error('Rate limit exceeded'),
      );

      await expect(service.login(loginDto)).rejects.toThrow();

      expect(prisma.user.findFirst).not.toHaveBeenCalled();
      expect(events.emit).not.toHaveBeenCalled();
    });
  });

  // ── register ───────────────────────────────────────────────────────────────

  describe('register', () => {
    const registerDto: RegisterDto = {
      email: 'new@example.com',
      name: 'New User',
      password: 'Password1!',
      tenantId: 'tenant-1',
      rut: '12345678-9',
      phone: '+56912345678',
    };

    beforeEach(() => {
      prisma.user.findFirst.mockResolvedValue(null);
      prisma.role.findFirst.mockResolvedValue(mockRole);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');

      // Simulate the interactive $transaction(async tx => ...) callback.
      // We run the callback with a mock tx whose operations return mockUser,
      // then forward the { user, accessToken, refreshToken } shape the service
      // returns from the transaction body.
      prisma.$transaction.mockImplementation(async (cb: unknown) => {
        if (typeof cb !== 'function') return cb;
        const mockTx = {
          user: {
            create: jest.fn().mockResolvedValue(mockUser),
            update: jest.fn().mockResolvedValue(mockUser),
          },
        };
        return (cb as (tx: typeof mockTx) => Promise<unknown>)(mockTx);
      });
    });

    it('should run the create + update in a single transaction', async () => {
      await service.register(registerDto);

      expect(prisma.$transaction).toHaveBeenCalledTimes(1);
    });

    it('should return a valid auth response', async () => {
      const result = await service.register(registerDto);

      expect(result).toMatchObject<Partial<AuthResponseDto>>({
        accessToken: 'mock-token',
        refreshToken: 'mock-token',
      });
    });

    it('should look up the role by id when roleId is provided', async () => {
      await service.register({ ...registerDto, roleId: 'custom-role-id' });

      expect(prisma.role.findFirst).toHaveBeenCalledWith({
        where: { id: 'custom-role-id' },
      });
    });

    it('should throw BadRequestException when provided roleId does not exist', async () => {
      prisma.role.findFirst.mockResolvedValueOnce(null);

      await expect(
        service.register({ ...registerDto, roleId: 'non-existent-role' }),
      ).rejects.toThrow('Provided roleId does not exist');
    });

    it('should look up the default role when roleId is not provided', async () => {
      await service.register(registerDto);

      expect(prisma.role.findFirst).toHaveBeenCalledWith({
        where: { tenantId: registerDto.tenantId, name: 'User' },
      });
    });

    it('should throw BadRequestException when user already exists', async () => {
      prisma.user.findFirst.mockResolvedValue(mockUser);

      await expect(service.register(registerDto)).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw BadRequestException when no default role exists', async () => {
      prisma.role.findFirst.mockResolvedValueOnce(null);

      await expect(service.register(registerDto)).rejects.toThrow(
        'No default role found for tenant',
      );
    });

    it('should emit user.created event after registration', async () => {
      await service.register(registerDto);

      expect(events.emit).toHaveBeenCalledWith(
        'user.created',
        expect.objectContaining({
          userId: mockUser.id,
          email: mockUser.email,
        }),
      );
    });

    it('should hash the password with bcrypt before storing', async () => {
      await service.register(registerDto);

      expect(bcrypt.hash).toHaveBeenCalledWith(registerDto.password, 10);
    });

    describe('password strength validation', () => {
      it.each([
        ['too short', 'Ab1!'],
        ['no uppercase letter', 'password1!'],
        ['no lowercase letter', 'PASSWORD1!'],
        ['no digit', 'Password!'],
        ['no special character', 'Password1'],
      ])(
        'should reject a password with %s',
        async (_label: string, password: string) => {
          await expect(
            service.register({ ...registerDto, password }),
          ).rejects.toThrow(BadRequestException);
        },
      );

      it('should accept a valid strong password', async () => {
        await expect(
          service.register({ ...registerDto, password: 'StrongPass1!' }),
        ).resolves.toBeDefined();
      });
    });
  });

  // ── refreshToken ───────────────────────────────────────────────────────────

  describe('refreshToken', () => {
    const dto: RefreshTokenDto = { refreshToken: 'valid-refresh-token' };

    beforeEach(() => {
      jwt.verify.mockReturnValue({ sub: mockUser.id });
      prisma.user.findFirst.mockResolvedValue(mockUser);
      jwt.sign.mockReturnValue('new-access-token');
    });

    it('should return a new access token for a valid refresh token', async () => {
      const result = await service.refreshToken(dto);

      expect(result).toEqual<{ accessToken: string }>({
        accessToken: 'new-access-token',
      });
    });

    it('should verify the token using the refresh secret', async () => {
      await service.refreshToken(dto);

      expect(jwt.verify).toHaveBeenCalledWith(
        dto.refreshToken,
        expect.objectContaining({ secret: 'test-refresh-secret' }),
      );
    });

    it('should look up the user by the hashed token, not the raw value', async () => {
      await service.refreshToken(dto);

      expect(prisma.user.findFirst).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            refreshToken: hashToken(dto.refreshToken),
          }),
        }),
      );
    });

    it('should throw UnauthorizedException when user is not found', async () => {
      prisma.user.findFirst.mockResolvedValue(null);

      await expect(service.refreshToken(dto)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when jwt.verify throws', async () => {
      jwt.verify.mockImplementation(() => {
        throw new Error('jwt expired');
      });

      await expect(service.refreshToken(dto)).rejects.toThrow(
        'Invalid or expired refresh token',
      );
    });
  });

  // ── logout ─────────────────────────────────────────────────────────────────

  describe('logout', () => {
    beforeEach(() => {
      prisma.user.update.mockResolvedValue(mockUser);
    });

    it('should clear refreshToken and tokenExpiry in the database', async () => {
      await service.logout(mockUser.id);

      expect(prisma.user.update).toHaveBeenCalledWith({
        where: { id: mockUser.id },
        data: { refreshToken: null, tokenExpiry: null },
      });
    });

    it('should blacklist the token via RateLimiterService when provided', async () => {
      await service.logout(mockUser.id, 'some-jwt-token');

      expect(rateLimiter.blacklistToken).toHaveBeenCalledWith(
        'some-jwt-token',
        15 * 60,
      );
    });

    it('should not call blacklistToken when no token is passed', async () => {
      await service.logout(mockUser.id);

      expect(rateLimiter.blacklistToken).not.toHaveBeenCalled();
    });

    it('should emit user.logout event', async () => {
      await service.logout(mockUser.id);

      expect(events.emit).toHaveBeenCalledWith(
        'user.logout',
        expect.objectContaining({ userId: mockUser.id }),
      );
    });
  });

  // ── revokeAllSessions ──────────────────────────────────────────────────────

  describe('revokeAllSessions', () => {
    beforeEach(() => {
      prisma.user.update.mockResolvedValue(mockUser);
    });

    it('should nullify refreshToken when no exceptToken is given', async () => {
      await service.revokeAllSessions(mockUser.id);

      expect(prisma.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            refreshToken: null,
            tokenExpiry: null,
          }),
        }),
      );
    });

    it('should store a hashed exceptToken when provided', async () => {
      await service.revokeAllSessions(mockUser.id, 'keep-this-token');

      expect(prisma.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            refreshToken: hashToken('keep-this-token'),
          }),
        }),
      );
    });

    it('should emit user.sessions.revoked event with the raw exceptToken', async () => {
      await service.revokeAllSessions(mockUser.id, 'keep-this-token');

      expect(events.emit).toHaveBeenCalledWith(
        'user.sessions.revoked',
        expect.objectContaining({
          userId: mockUser.id,
          exceptToken: 'keep-this-token',
        }),
      );
    });
  });

  // ── isTokenBlacklisted ─────────────────────────────────────────────────────

  describe('isTokenBlacklisted', () => {
    it('should return false when RateLimiterService reports the token is clean', async () => {
      rateLimiter.isTokenBlacklisted.mockResolvedValueOnce(false);

      await expect(service.isTokenBlacklisted('clean-token')).resolves.toBe(
        false,
      );
    });

    it('should return true when RateLimiterService reports the token is blacklisted', async () => {
      rateLimiter.isTokenBlacklisted.mockResolvedValueOnce(true);

      await expect(
        service.isTokenBlacklisted('blacklisted-token'),
      ).resolves.toBe(true);
    });

    it('should delegate to RateLimiterService with the correct token', async () => {
      await service.isTokenBlacklisted('some-token');

      expect(rateLimiter.isTokenBlacklisted).toHaveBeenCalledWith('some-token');
    });
  });

  // ── validateUser ───────────────────────────────────────────────────────────

  describe('validateUser', () => {
    const fullMockUser = {
      ...mockUser,
      tenant: { id: 'tenant-1', name: 'Tenant One' },
    };

    it('should return a safe JwtUser object without sensitive fields', async () => {
      prisma.user.findUnique.mockResolvedValue(fullMockUser);

      const result = await service.validateUser(mockUser.id);

      const expected: JwtUser = {
        id: mockUser.id,
        email: mockUser.email,
        name: mockUser.name,
        tenantId: mockUser.tenantId,
        role: mockRole.name,
        permissions: ['read:profile'],
      };
      expect(result).toEqual(expected);
      expect(result).not.toHaveProperty('passwordHash');
    });

    it('should return null when user is not found', async () => {
      prisma.user.findUnique.mockResolvedValue(null);

      const result = await service.validateUser('non-existent-id');

      expect(result).toBeNull();
    });

    it('should return null when prisma throws an error', async () => {
      prisma.user.findUnique.mockRejectedValue(
        new Error('DB connection error'),
      );

      const result = await service.validateUser(mockUser.id);

      expect(result).toBeNull();
    });
  });
});
