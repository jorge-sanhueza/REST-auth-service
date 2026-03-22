import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  IsUUID,
  MinLength,
  IsOptional,
} from 'class-validator';

export class LoginDto {
  @ApiProperty({
    description: 'The registered email address of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'The account password (min 6 characters)',
    example: 'Password123',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiPropertyOptional({
    description: 'UUID of the tenant for multi-tenant environments',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @IsUUID()
  @IsOptional()
  tenantId?: string;
}

export class RegisterDto {
  @ApiProperty({
    description: 'User email address',
    example: 'newuser@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'Full name of the user', example: 'Juan García' })
  @IsString()
  name: string;

  @ApiProperty({
    description: 'Secure password for the new account',
    example: 'SecurePass123!',
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiPropertyOptional({
    description: 'RUT',
    example: '12.345.678-9',
  })
  @IsString()
  @IsOptional()
  rut?: string;

  @ApiPropertyOptional({
    description: 'Phone number',
    example: '+56950109999',
  })
  @IsString()
  @IsOptional()
  phone?: string;

  @ApiProperty({ description: 'The unique identifier for the assigned tenant' })
  @IsUUID()
  tenantId: string;

  @ApiPropertyOptional({
    description: 'The unique identifier for the user role',
    example: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
  })
  @IsUUID()
  @IsOptional()
  roleId?: string;
}

export class RefreshTokenDto {
  @ApiProperty({ description: 'The valid refresh token string' })
  @IsString()
  refreshToken: string;
}

export class LogoutDto {
  @ApiProperty({ description: 'ID of the user logging out' })
  @IsUUID()
  userId: string;

  @ApiPropertyOptional({ description: 'The refresh token to be invalidated' })
  @IsString()
  @IsOptional()
  refreshToken?: string;
}

export class UserDetailsDto {
  @ApiProperty({ example: 'uuid-v4-id' })
  id: string;

  @ApiProperty({ example: 'user@example.com' })
  email: string;

  @ApiProperty({ example: 'Juan Perez' })
  name: string;

  @ApiProperty({ example: 'uuid-v4-tenant' })
  tenantId: string;

  @ApiProperty({ example: 'admin' })
  role: string;

  @ApiProperty({ type: [String], example: ['read:users', 'write:users'] })
  permissions: string[];
}

export class AuthResponseDto {
  @ApiProperty({
    description: 'JWT Access Token used for authenticated requests',
  })
  accessToken: string;

  @ApiProperty({ description: 'Token used to obtain a new access token' })
  refreshToken: string;

  @ApiProperty({ type: UserDetailsDto })
  user: UserDetailsDto;
}
