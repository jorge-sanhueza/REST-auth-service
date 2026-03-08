import {
  IsEmail,
  IsString,
  IsOptional,
  IsBoolean,
  IsUUID,
  MinLength,
  IsEnum,
} from 'class-validator';
import { Transform } from 'class-transformer';

export enum UserStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  SUSPENDED = 'SUSPENDED',
}

export class CreateUserDto {
  @IsEmail()
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  email: string;

  @IsString()
  @MinLength(2)
  name: string;

  @IsString()
  @MinLength(6)
  password: string;

  @IsString()
  @IsOptional()
  @Transform(({ value }: { value: string }) => value?.trim())
  rut?: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsUUID()
  @IsOptional()
  roleId?: string;

  @IsEnum(UserStatus)
  @IsOptional()
  status?: UserStatus = UserStatus.ACTIVE;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean = true;
}

export class UpdateUserDto {
  @IsEmail()
  @IsOptional()
  @Transform(({ value }: { value: string }) => value?.toLowerCase().trim())
  email?: string;

  @IsString()
  @MinLength(2)
  @IsOptional()
  name?: string;

  @IsString()
  @MinLength(6)
  @IsOptional()
  password?: string;

  @IsString()
  @IsOptional()
  @Transform(({ value }: { value: string }) => value?.trim())
  rut?: string;

  @IsString()
  @IsOptional()
  phone?: string;

  @IsUUID()
  @IsOptional()
  roleId?: string;

  @IsEnum(UserStatus)
  @IsOptional()
  status?: UserStatus;

  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}

export class UserResponseDto {
  id: string;
  email: string;
  name: string;
  rut?: string | null;
  phone?: string | null;
  isActive: boolean;
  status: UserStatus;
  lastLoginAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
  role: {
    id: string;
    name: string;
    permissions: string[];
  };
  tenantId: string;
}

export class UserListResponseDto {
  data: UserResponseDto[];
  total: number;
  page: number;
  limit: number;
}
