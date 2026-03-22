import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  HttpCode,
  HttpStatus,
  Req,
  Delete,
} from '@nestjs/common';
import { type Request } from 'express';
import { AuthService } from './auth.service';
import {
  LoginDto,
  RegisterDto,
  RefreshTokenDto,
  AuthResponseDto,
} from './dto/auth.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { PermissionsGuard } from './guards/permissions.guard';
import { CurrentUser } from './decorators/user.decorator';
import { Permissions } from './decorators/permissions.decorator';
import { type TenantRequest } from '../common/middleware/tenant.middleware';
import { type JwtUser } from './interfaces/auth.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
  ): Promise<AuthResponseDto> {
    // metadata for audit logging
    return this.authService.login(loginDto, {
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto): Promise<AuthResponseDto> {
    // If tenantId not provided in DTO, it might come from middleware
    // But for registration, tenantId is usually required
    return this.authService.register(registerDto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<{ accessToken: string }> {
    return this.authService.refreshToken(refreshTokenDto);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: JwtUser,
    @Req() req: TenantRequest, // Use extended request type
  ): Promise<{ message: string }> {
    const token = req.headers.authorization?.split(' ')[1];
    await this.authService.logout(user.id, token);

    // Log the tenant context
    console.log(`User ${user.id} logged out from tenant ${req.tenantId}`);

    return { message: 'Logged out successfully' };
  }

  @Delete('sessions')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async revokeAllSessions(
    @CurrentUser() user: JwtUser,
    @Req() req: TenantRequest,
  ): Promise<{ message: string }> {
    const currentToken = req.headers.authorization?.split(' ')[1];
    await this.authService.revokeAllSessions(user.id, currentToken);
    return { message: 'All other sessions revoked' };
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  getProfile(@CurrentUser() user: JwtUser): JwtUser {
    return user;
  }

  @Get('tenant-info')
  @UseGuards(JwtAuthGuard)
  getTenantInfo(
    @CurrentUser() user: JwtUser,
    @Req() req: TenantRequest,
  ): {
    userTenant: string;
    effectiveTenant: string;
    isCrossTenant: boolean;
  } {
    return {
      userTenant: user.tenantId,
      effectiveTenant: req.tenantId!,
      isCrossTenant: user.tenantId !== req.tenantId,
    };
  }

  @Get('admin-only')
  @UseGuards(JwtAuthGuard, PermissionsGuard)
  @Permissions('admin:access')
  adminOnly(): { message: string } {
    return { message: 'This is admin only' };
  }
}
