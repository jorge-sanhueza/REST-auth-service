import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisEventService } from '../events/redis-event.service';
import * as bcrypt from 'bcrypt';
import { Prisma, User, Role } from '@prisma/client';
import {
  CreateUserDto,
  UpdateUserDto,
  UserResponseDto,
  UserStatus,
} from './dto/create-user.dto';

type UserWithRole = User & { role: Role };

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private prisma: PrismaService,
    private eventService: RedisEventService,
  ) {}

  async create(
    createUserDto: CreateUserDto,
    tenantId: string,
    createdBy: string,
  ): Promise<UserResponseDto> {
    const { email, name, password, rut, phone, roleId, isActive } =
      createUserDto;

    const existingUser = await this.prisma.user.findFirst({
      where: { email, tenantId },
    });

    if (existingUser) {
      throw new BadRequestException('User already exists in this tenant');
    }

    let finalRoleId = roleId;
    if (!finalRoleId) {
      const defaultRole = await this.prisma.role.findFirst({
        where: { tenantId, name: 'User' },
      });

      if (!defaultRole) {
        throw new BadRequestException(
          'No default role found for tenant. Please create a role first.',
        );
      }

      finalRoleId = defaultRole.id;
    } else {
      const role = await this.prisma.role.findFirst({
        where: { id: finalRoleId, tenantId },
      });

      if (!role) {
        throw new BadRequestException('Role not found in this tenant');
      }
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: {
        email,
        name,
        passwordHash,
        rut,
        phone,
        isActive: isActive ?? true,
        tenantId,
        roleId: finalRoleId,
      },
      include: { role: true },
    });

    await this.prisma.auditLog.create({
      data: {
        userId: user.id,
        userEmail: user.email,
        tenantId,
        action: 'USER_CREATED',
        status: 'SUCCESS',
        details: { createdBy } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('user.created', {
      userId: user.id,
      email: user.email,
      name: user.name,
      tenantId: user.tenantId,
      role: user.role.name,
      permissions: user.role.permissions,
      timestamp: new Date(),
    });

    this.logger.log(`User created: ${user.email} in tenant ${tenantId}`);

    return this.mapToResponse(user);
  }

  async findAll(
    tenantId: string,
    page = 1,
    limit = 10,
    search?: string,
    roleId?: string,
    isActive?: boolean,
  ): Promise<{
    data: UserResponseDto[];
    total: number;
    page: number;
    limit: number;
  }> {
    const skip = (page - 1) * limit;

    const where: Prisma.UserWhereInput = {
      tenantId,
      ...(search && {
        OR: [
          { email: { contains: search, mode: 'insensitive' } },
          { name: { contains: search, mode: 'insensitive' } },
          { rut: { contains: search, mode: 'insensitive' } },
        ],
      }),
      ...(roleId && { roleId }),
      ...(isActive !== undefined && { isActive }),
    };

    const [users, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        include: { role: true },
        skip,
        take: limit,
        orderBy: { createdAt: 'desc' },
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      data: users.map((user) => this.mapToResponse(user)),
      total,
      page,
      limit,
    };
  }

  async findOne(id: string, tenantId: string): Promise<UserResponseDto> {
    const user = await this.prisma.user.findFirst({
      where: { id, tenantId },
      include: { role: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.mapToResponse(user);
  }

  async update(
    id: string,
    tenantId: string,
    updateUserDto: UpdateUserDto,
    updatedBy: string,
  ): Promise<UserResponseDto> {
    const user = await this.prisma.user.findFirst({
      where: { id, tenantId },
      include: { role: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (updateUserDto.email && updateUserDto.email !== user.email) {
      const existingUser = await this.prisma.user.findFirst({
        where: { email: updateUserDto.email, tenantId, NOT: { id } },
      });

      if (existingUser) {
        throw new BadRequestException('Email already exists in this tenant');
      }
    }

    if (updateUserDto.roleId && updateUserDto.roleId !== user.roleId) {
      const role = await this.prisma.role.findFirst({
        where: { id: updateUserDto.roleId, tenantId },
      });

      if (!role) {
        throw new BadRequestException('Role not found in this tenant');
      }
    }

    const updateData: Prisma.UserUpdateInput = {
      ...(updateUserDto.email && { email: updateUserDto.email }),
      ...(updateUserDto.name && { name: updateUserDto.name }),
      ...(updateUserDto.phone !== undefined && { phone: updateUserDto.phone }),
      ...(updateUserDto.rut !== undefined && { rut: updateUserDto.rut }),
      ...(updateUserDto.isActive !== undefined && {
        isActive: updateUserDto.isActive,
      }),
      ...(updateUserDto.roleId && {
        role: { connect: { id: updateUserDto.roleId } },
      }),
      ...(updateUserDto.password && {
        passwordHash: await bcrypt.hash(updateUserDto.password, 10),
      }),
    };

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data: updateData,
      include: { role: true },
    });

    await this.prisma.auditLog.create({
      data: {
        userId: updatedUser.id,
        userEmail: updatedUser.email,
        tenantId,
        action: 'USER_UPDATED',
        status: 'SUCCESS',
        details: {
          updatedBy,
          changes: Object.keys(updateUserDto),
        } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('user.updated', {
      userId: updatedUser.id,
      email: updatedUser.email,
      tenantId: updatedUser.tenantId,
      changes: Object.keys(updateUserDto),
      timestamp: new Date(),
    });

    this.logger.log(`User updated: ${updatedUser.email}`);

    return this.mapToResponse(updatedUser);
  }

  async deactivate(
    id: string,
    tenantId: string,
    deactivatedBy: string,
  ): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: { id, tenantId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.update({
      where: { id },
      data: { isActive: false, refreshToken: null, tokenExpiry: null },
    });

    await this.prisma.auditLog.create({
      data: {
        userId: user.id,
        userEmail: user.email,
        tenantId,
        action: 'USER_DEACTIVATED',
        status: 'SUCCESS',
        details: { deactivatedBy } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('user.deactivated', {
      userId: user.id,
      email: user.email,
      tenantId: user.tenantId,
      timestamp: new Date(),
    });

    this.logger.log(`User deactivated: ${user.email}`);
  }

  async activate(
    id: string,
    tenantId: string,
    activatedBy: string,
  ): Promise<UserResponseDto> {
    const user = await this.prisma.user.findFirst({
      where: { id, tenantId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = await this.prisma.user.update({
      where: { id },
      data: { isActive: true },
      include: { role: true },
    });

    await this.prisma.auditLog.create({
      data: {
        userId: user.id,
        userEmail: user.email,
        tenantId,
        action: 'USER_ACTIVATED',
        status: 'SUCCESS',
        details: { activatedBy } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('user.activated', {
      userId: user.id,
      email: user.email,
      tenantId: user.tenantId,
      timestamp: new Date(),
    });

    this.logger.log(`User activated: ${user.email}`);

    return this.mapToResponse(updatedUser);
  }

  async delete(id: string, tenantId: string, deletedBy: string): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: { id, tenantId },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    await this.prisma.user.delete({ where: { id } });

    await this.prisma.auditLog.create({
      data: {
        userId: user.id,
        userEmail: user.email,
        tenantId,
        action: 'USER_DELETED',
        status: 'SUCCESS',
        details: { deletedBy } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('user.deleted', {
      userId: user.id,
      email: user.email,
      tenantId: user.tenantId,
      timestamp: new Date(),
    });

    this.logger.log(`User deleted: ${user.email}`);
  }

  async findByEmail(
    email: string,
    tenantId: string,
  ): Promise<UserResponseDto | null> {
    const user = await this.prisma.user.findFirst({
      where: { email, tenantId },
      include: { role: true },
    });

    return user ? this.mapToResponse(user) : null;
  }

  async updateLastLogin(id: string): Promise<void> {
    await this.prisma.user.update({
      where: { id },
      data: { lastLoginAt: new Date() },
    });
  }

  async validateUserExists(userId: string, tenantId: string): Promise<boolean> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, tenantId, isActive: true },
    });
    return !!user;
  }

  private mapToResponse(user: UserWithRole): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      rut: user.rut,
      phone: user.phone,
      isActive: user.isActive,
      status: user.isActive ? UserStatus.ACTIVE : UserStatus.INACTIVE,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      role: {
        id: user.role.id,
        name: user.role.name,
        permissions: user.role.permissions as string[],
      },
      tenantId: user.tenantId,
    };
  }
}
