import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  HttpStatus,
  HttpCode,
  ParseUUIDPipe,
  DefaultValuePipe,
  ParseIntPipe,
} from '@nestjs/common';
import { RolesService } from './roles.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../auth/guards/permissions.guard';
import { Permissions } from '../auth/decorators/permissions.decorator';
import { CurrentUser } from '../auth/decorators/user.decorator';
import {
  CreateRoleDto,
  UpdateRoleDto,
  RoleResponseDto,
} from './dto/create-role.dto';
import { type JwtUser } from '@/auth/interfaces/auth.interface';

@Controller('roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post()
  @Permissions('roles:create')
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() createRoleDto: CreateRoleDto,
    @CurrentUser() user: JwtUser,
  ): Promise<RoleResponseDto> {
    return this.rolesService.create(createRoleDto, user.tenantId, user.id);
  }

  @Get()
  @Permissions('roles:read')
  async findAll(
    @CurrentUser() user: JwtUser,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number,
    @Query('search') search?: string,
    @Query('includeInactive') includeInactive?: string,
  ): Promise<{
    data: RoleResponseDto[];
    total: number;
    page: number;
    limit: number;
  }> {
    return this.rolesService.findAll(
      user.tenantId,
      page,
      limit,
      search,
      this.parseOptionalBool(includeInactive),
    );
  }

  @Get('permissions/available')
  @Permissions('roles:read')
  async getAvailablePermissions(): Promise<Record<string, string[]>> {
    return await this.rolesService.getAvailablePermissions();
  }

  @Get('default')
  @Permissions('roles:read')
  async getDefaultRole(
    @CurrentUser() user: JwtUser,
  ): Promise<RoleResponseDto | null> {
    return this.rolesService.getDefaultRole(user.tenantId);
  }

  @Get(':id')
  @Permissions('roles:read')
  async findOne(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<RoleResponseDto> {
    return this.rolesService.findOne(id, user.tenantId);
  }

  @Get(':id/permissions')
  @Permissions('roles:read')
  async getPermissions(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<string[]> {
    return this.rolesService.getPermissions(id, user.tenantId);
  }

  @Patch(':id')
  @Permissions('roles:update')
  async update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateRoleDto: UpdateRoleDto,
    @CurrentUser() user: JwtUser,
  ): Promise<RoleResponseDto> {
    return this.rolesService.update(id, user.tenantId, updateRoleDto, user.id);
  }

  @Patch(':id/permissions')
  @Permissions('roles:update')
  async updatePermissions(
    @Param('id', ParseUUIDPipe) id: string,
    @Body('permissions') permissions: string[],
    @CurrentUser() user: JwtUser,
  ): Promise<RoleResponseDto> {
    return this.rolesService.updatePermissions(
      id,
      user.tenantId,
      permissions,
      user.id,
    );
  }

  @Delete(':id')
  @Permissions('roles:delete')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<void> {
    await this.rolesService.delete(id, user.tenantId, user.id);
  }

  private parseOptionalBool(value: string | undefined): boolean | undefined {
    if (value === 'true') return true;
    if (value === 'false') return false;
    return undefined;
  }
}
