import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RedisEventService } from '../events/redis-event.service';
import { Prisma, Role } from '@prisma/client';
import {
  CreateRoleDto,
  UpdateRoleDto,
  RoleResponseDto,
} from './dto/create-role.dto';
import { getAllPermissions } from './constants/permissions.constants';

@Injectable()
export class RolesService {
  private readonly logger = new Logger(RolesService.name);

  constructor(
    private prisma: PrismaService,
    private eventService: RedisEventService,
  ) {}

  async create(
    createRoleDto: CreateRoleDto,
    tenantId: string,
    createdBy: string,
  ): Promise<RoleResponseDto> {
    const { name, description, permissions, isActive } = createRoleDto;

    // Check if role with same name exists in tenant
    const existingRole = await this.prisma.role.findFirst({
      where: { name, tenantId },
    });

    if (existingRole) {
      throw new ConflictException(
        `Role with name "${name}" already exists in this tenant`,
      );
    }

    // Validate permissions format
    this.validatePermissions(permissions);

    const role = await this.prisma.role.create({
      data: {
        name,
        description,
        permissions: permissions as Prisma.InputJsonValue,
        tenantId,
        isActive: isActive ?? true,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        userId: createdBy,
        userEmail: null,
        tenantId,
        action: 'ROLE_CREATED',
        status: 'SUCCESS',
        details: {
          roleId: role.id,
          roleName: role.name,
          createdBy,
          permissions,
        } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('role.created', {
      roleId: role.id,
      name: role.name,
      tenantId: role.tenantId,
      permissions: role.permissions,
      createdBy,
      timestamp: new Date(),
    });

    this.logger.log(`Role created: ${role.name} in tenant ${tenantId}`);

    return this.mapToResponse(role);
  }

  async findAll(
    tenantId: string,
    page = 1,
    limit = 10,
    search?: string,
    includeInactive = false,
  ): Promise<{
    data: RoleResponseDto[];
    total: number;
    page: number;
    limit: number;
  }> {
    const skip = (page - 1) * limit;

    const where: Prisma.RoleWhereInput = {
      tenantId,
      ...(search && {
        OR: [
          { name: { contains: search, mode: 'insensitive' } },
          { description: { contains: search, mode: 'insensitive' } },
        ],
      }),
      ...(!includeInactive && { isActive: true }),
    };

    const [roles, total] = await Promise.all([
      this.prisma.role.findMany({
        where,
        include: {
          _count: {
            select: { users: true },
          },
        },
        skip,
        take: limit,
        orderBy: [{ isSystem: 'desc' }, { name: 'asc' }],
      }),
      this.prisma.role.count({ where }),
    ]);

    return {
      data: roles.map((role) => ({
        ...this.mapToResponse(role),
        usersCount: role._count.users,
      })),
      total,
      page,
      limit,
    };
  }

  async findOne(id: string, tenantId: string): Promise<RoleResponseDto> {
    const role = await this.prisma.role.findFirst({
      where: { id, tenantId },
      include: {
        _count: {
          select: { users: true },
        },
        users: {
          select: {
            id: true,
            name: true,
            email: true,
            isActive: true,
          },
          take: 10, // Limit to 10 users for performance
        },
      },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return {
      ...this.mapToResponse(role),
      usersCount: role._count.users,
      users: role.users,
    };
  }

  async update(
    id: string,
    tenantId: string,
    updateRoleDto: UpdateRoleDto,
    updatedBy: string,
  ): Promise<RoleResponseDto> {
    const role = await this.prisma.role.findFirst({
      where: { id, tenantId },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    // Prevent modification of system roles except for permissions and isActive
    if (role.isSystem && updateRoleDto.name) {
      throw new BadRequestException('Cannot rename system roles');
    }

    if (updateRoleDto.name && updateRoleDto.name !== role.name) {
      const existingRole = await this.prisma.role.findFirst({
        where: { name: updateRoleDto.name, tenantId, NOT: { id } },
      });

      if (existingRole) {
        throw new ConflictException(
          `Role with name "${updateRoleDto.name}" already exists`,
        );
      }
    }

    if (updateRoleDto.permissions) {
      this.validatePermissions(updateRoleDto.permissions);
    }

    const updateData: Prisma.RoleUpdateInput = {
      ...(updateRoleDto.name && { name: updateRoleDto.name }),
      ...(updateRoleDto.description !== undefined && {
        description: updateRoleDto.description,
      }),
      ...(updateRoleDto.permissions && {
        permissions: updateRoleDto.permissions as Prisma.InputJsonValue,
      }),
      ...(updateRoleDto.isActive !== undefined && {
        isActive: updateRoleDto.isActive,
      }),
    };

    const updatedRole = await this.prisma.role.update({
      where: { id },
      data: updateData,
    });

    await this.prisma.auditLog.create({
      data: {
        tenantId,
        action: 'ROLE_UPDATED',
        status: 'SUCCESS',
        details: {
          roleId: updatedRole.id,
          roleName: updatedRole.name,
          updatedBy,
          changes: Object.keys(updateRoleDto),
        } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('role.updated', {
      roleId: updatedRole.id,
      name: updatedRole.name,
      tenantId: updatedRole.tenantId,
      changes: Object.keys(updateRoleDto),
      updatedBy,
      timestamp: new Date(),
    });

    this.logger.log(`Role updated: ${updatedRole.name}`);

    return this.mapToResponse(updatedRole);
  }

  async delete(id: string, tenantId: string, deletedBy: string): Promise<void> {
    const role = await this.prisma.role.findFirst({
      where: { id, tenantId },
      include: {
        _count: {
          select: { users: true },
        },
      },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    if (role.isSystem) {
      throw new BadRequestException('Cannot delete system roles');
    }

    if (role._count.users > 0) {
      throw new BadRequestException(
        `Cannot delete role "${role.name}" because it has ${role._count.users} assigned users. Reassign these users first.`,
      );
    }

    await this.prisma.$transaction([
      this.prisma.auditLog.create({
        data: {
          tenantId,
          action: 'ROLE_DELETED',
          status: 'SUCCESS',
          details: {
            roleId: role.id,
            roleName: role.name,
            deletedBy,
          } as Prisma.InputJsonValue,
        },
      }),
      this.prisma.role.delete({
        where: { id },
      }),
    ]);

    await this.eventService.emit('role.deleted', {
      roleId: role.id,
      name: role.name,
      tenantId: role.tenantId,
      deletedBy,
      timestamp: new Date(),
    });

    this.logger.log(`Role deleted: ${role.name}`);
  }

  async getPermissions(id: string, tenantId: string): Promise<string[]> {
    const role = await this.prisma.role.findFirst({
      where: { id, tenantId, isActive: true },
    });

    if (!role) {
      throw new NotFoundException('Role not found or inactive');
    }

    return role.permissions as string[];
  }

  async updatePermissions(
    id: string,
    tenantId: string,
    permissions: string[],
    updatedBy: string,
  ): Promise<RoleResponseDto> {
    this.validatePermissions(permissions);

    const role = await this.prisma.role.findFirst({
      where: { id, tenantId },
    });

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    const updatedRole = await this.prisma.role.update({
      where: { id },
      data: {
        permissions: permissions as Prisma.InputJsonValue,
      },
    });

    await this.prisma.auditLog.create({
      data: {
        tenantId,
        action: 'ROLE_PERMISSIONS_UPDATED',
        status: 'SUCCESS',
        details: {
          roleId: updatedRole.id,
          roleName: updatedRole.name,
          updatedBy,
          permissions,
        } as Prisma.InputJsonValue,
      },
    });

    await this.eventService.emit('role.permissions.updated', {
      roleId: updatedRole.id,
      name: updatedRole.name,
      tenantId: updatedRole.tenantId,
      permissions,
      updatedBy,
      timestamp: new Date(),
    });

    this.logger.log(`Permissions updated for role: ${updatedRole.name}`);

    return this.mapToResponse(updatedRole);
  }

  async validateRoleExists(roleId: string, tenantId: string): Promise<boolean> {
    const role = await this.prisma.role.findFirst({
      where: { id: roleId, tenantId, isActive: true },
    });
    return !!role;
  }

  async getDefaultRole(tenantId: string): Promise<RoleResponseDto | null> {
    const role = await this.prisma.role.findFirst({
      where: { tenantId, name: 'User', isActive: true },
    });

    return role ? this.mapToResponse(role) : null;
  }

  async getAvailablePermissions(): Promise<Record<string, string[]>> {
    return await Promise.resolve(getAllPermissions());
  }

  private validatePermissions(permissions: string[]): void {
    // Valid patterns:
    // - resource:action (e.g., "orders:create")
    // - resource:* (e.g., "orders:*")
    // - * (wildcard for everything)
    const validPermissionPattern = /^([a-z]+|\*):([a-z]+|\*)$|^\*$/;

    const invalidPermissions = permissions.filter(
      (p) => !validPermissionPattern.test(p),
    );

    if (invalidPermissions.length > 0) {
      throw new BadRequestException(
        `Invalid permission format: ${invalidPermissions.join(', ')}. ` +
          `Permissions should follow the pattern "resource:action", "resource:*", or "*"`,
      );
    }

    // Additional validation: if "*" is present, it should be the only permission
    if (permissions.includes('*') && permissions.length > 1) {
      throw new BadRequestException(
        'When using wildcard "*", it should be the only permission',
      );
    }
  }

  private mapToResponse(role: Role): RoleResponseDto {
    return {
      id: role.id,
      name: role.name,
      description: role.description,
      permissions: role.permissions as string[],
      tenantId: role.tenantId,
      isSystem: role.isSystem,
      isActive: role.isActive,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    };
  }
}
