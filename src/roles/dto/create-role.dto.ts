import {
  IsString,
  IsOptional,
  IsArray,
  IsBoolean,
  IsNotEmpty,
  MinLength,
  MaxLength,
  ArrayNotEmpty,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateRoleDto {
  @ApiProperty({ example: 'Admin', description: 'Role name' })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(50)
  name: string;

  @ApiProperty({
    example: 'Administrator role with full access',
    required: false,
  })
  @IsString()
  @IsOptional()
  @MaxLength(200)
  description?: string;

  @ApiProperty({
    example: ['users:read', 'users:write', 'roles:manage'],
    description: 'Array of permission strings',
  })
  @IsArray()
  @ArrayNotEmpty()
  @IsString({ each: true })
  permissions: string[];

  @ApiProperty({ example: true, required: false, default: true })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}

export class UpdateRoleDto {
  @ApiProperty({ example: 'Admin', required: false })
  @IsString()
  @IsOptional()
  @MinLength(2)
  @MaxLength(50)
  name?: string;

  @ApiProperty({ example: 'Updated description', required: false })
  @IsString()
  @IsOptional()
  @MaxLength(200)
  description?: string;

  @ApiProperty({
    example: ['users:read', 'users:write', 'roles:manage'],
    required: false,
  })
  @IsArray()
  @IsOptional()
  @IsString({ each: true })
  permissions?: string[];

  @ApiProperty({ example: true, required: false })
  @IsBoolean()
  @IsOptional()
  isActive?: boolean;
}

export class RoleResponseDto {
  id: string;
  name: string;
  description: string | null;
  permissions: string[];
  tenantId: string;
  isSystem: boolean;
  isActive: boolean;
  usersCount?: number;
  users?: Array<{
    id: string;
    name: string;
    email: string;
    isActive: boolean;
  }>;
  createdAt: Date;
  updatedAt: Date;
}

export class RoleListResponseDto {
  data: RoleResponseDto[];
  total: number;
  page: number;
  limit: number;
}
