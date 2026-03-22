import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import * as pg from 'pg';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);
  private readonly pool: pg.Pool;

  constructor() {
    const { Pool } = pg;
    const dbUrl = process.env.DATABASE_URL;

    // 1. Instantiate the pool first
    const poolInstance = new Pool({
      connectionString: dbUrl,
      max: (process.env.NODE_ENV === 'production' ? 20 : 10) as number,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    // Handle pool errors
    poolInstance.on('error', (err) => {
      this.logger.error('Unexpected database pool error', err.stack);
    });

    // 2. Pass the adapter to the parent PrismaClient constructor
    super({
      adapter: new PrismaPg(poolInstance as any),
      log:
        process.env.NODE_ENV === 'development'
          ? ['query', 'info', 'warn', 'error']
          : ['error'],
    });

    // 3. Store the reference for onModuleDestroy
    this.pool = poolInstance;
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('Successfully connected to database');
  }

  async onModuleDestroy() {
    await this.$disconnect();
    await this.pool.end();
    this.logger.log('Database connection closed');
  }
}
