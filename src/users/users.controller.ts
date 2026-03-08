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
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PermissionsGuard } from '../auth/guards/permissions.guard';
import { Permissions } from '../auth/decorators/permissions.decorator';
import { CurrentUser } from '../auth/decorators/user.decorator';
import {
  CreateUserDto,
  UpdateUserDto,
  UserResponseDto,
  UserListResponseDto,
} from './dto/create-user.dto';
import { type JwtUser } from '@/auth/dto/auth.dto';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  @UseGuards(PermissionsGuard)
  @Permissions('users:create')
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body() createUserDto: CreateUserDto,
    @CurrentUser() user: JwtUser,
  ): Promise<UserResponseDto> {
    return this.usersService.create(createUserDto, user.tenantId, user.id);
  }

  @Get()
  @UseGuards(PermissionsGuard)
  @Permissions('users:view')
  async findAll(
    @CurrentUser() user: JwtUser,
    @Query('page', new DefaultValuePipe(1), ParseIntPipe) page: number,
    @Query('limit', new DefaultValuePipe(10), ParseIntPipe) limit: number,
    @Query('search') search?: string,
    @Query('roleId') roleId?: string,
    @Query('isActive') isActive?: string,
  ): Promise<UserListResponseDto> {
    return this.usersService.findAll(
      user.tenantId,
      page,
      limit,
      search,
      roleId,
      this.parseOptionalBool(isActive),
    );
  }

  @Get('email/:email')
  @UseGuards(PermissionsGuard)
  @Permissions('users:view')
  async findByEmail(
    @Param('email') email: string,
    @CurrentUser() user: JwtUser,
  ): Promise<UserResponseDto | null> {
    return this.usersService.findByEmail(email, user.tenantId);
  }

  @Get(':id')
  @UseGuards(PermissionsGuard)
  @Permissions('users:view')
  async findOne(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<UserResponseDto> {
    return this.usersService.findOne(id, user.tenantId);
  }

  @Patch(':id')
  @UseGuards(PermissionsGuard)
  @Permissions('users:edit')
  async update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateUserDto: UpdateUserDto,
    @CurrentUser() user: JwtUser,
  ): Promise<UserResponseDto> {
    return this.usersService.update(id, user.tenantId, updateUserDto, user.id);
  }

  @Post(':id/activate')
  @UseGuards(PermissionsGuard)
  @Permissions('users:edit')
  async activate(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<UserResponseDto> {
    return this.usersService.activate(id, user.tenantId, user.id);
  }

  @Delete(':id/deactivate')
  @UseGuards(PermissionsGuard)
  @Permissions('users:delete')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deactivate(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<void> {
    await this.usersService.deactivate(id, user.tenantId, user.id);
  }

  @Delete(':id')
  @UseGuards(PermissionsGuard)
  @Permissions('users:delete')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentUser() user: JwtUser,
  ): Promise<void> {
    await this.usersService.delete(id, user.tenantId, user.id);
  }

  private parseOptionalBool(value: string | undefined): boolean | undefined {
    if (value === 'true') return true;
    if (value === 'false') return false;
    return undefined;
  }
}
