import {
  IsEmail,
  IsString,
  IsUUID,
  MinLength,
  IsOptional,
} from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsUUID()
  @IsOptional()
  tenantId?: string; // Optional if email is unique across tenants
}

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsString()
  @IsOptional()
  rut?: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsUUID()
  tenantId: string;

  @IsUUID()
  @IsOptional()
  roleId?: string; // If not provided, assign default role
}

export class RefreshTokenDto {
  @IsString()
  refreshToken: string;
}

export class LogoutDto {
  @IsUUID()
  userId: string;

  @IsString()
  @IsOptional()
  refreshToken?: string;
}

export class AuthResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    name: string;
    tenantId: string;
    role: string;
    permissions: string[];
  };
}

export interface JwtUser {
  id: string;
  email: string;
  name: string;
  tenantId: string;
  role: string;
  permissions: string[];
}
