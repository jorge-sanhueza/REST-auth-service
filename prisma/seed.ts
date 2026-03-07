import * as dotenv from 'dotenv';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import * as pg from 'pg';

dotenv.config();

const { Pool } = pg;
const dbUrl = process.env.DATABASE_URL;

if (!dbUrl) {
  throw new Error('DATABASE_URL environment variable is not set');
}

const pool = new Pool({
  connectionString: dbUrl,
  max: 1, // Seed only needs one connection
});

const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('🌱 Starting database seed...');

  // Create admin tenant
  const adminTenant = await prisma.tenant.upsert({
    where: { name: 'System Admin' },
    update: {},
    create: {
      name: 'System Admin',
      rut: '11111111-1',
      contact: 'admin@system.com',
      type: 'ADMIN',
      roles: {
        create: [
          {
            name: 'Super Admin',
            description: 'Full system access',
            isSystem: true,
            permissions: ['*'], // All permissions
          },
        ],
      },
    },
    include: { roles: true },
  });
  console.log('✅ Admin tenant created');

  // Create sample tenant
  const sampleTenant = await prisma.tenant.upsert({
    where: { name: 'Sample Transport Co' },
    update: {},
    create: {
      name: 'Sample Transport Co',
      rut: '22222222-2',
      contact: 'contact@sample.com',
      type: 'CARRIER',
      roles: {
        create: [
          {
            name: 'Admin',
            description: 'Tenant administrator',
            isSystem: true,
            permissions: [
              'users:*',
              'orders:*',
              'reports:*',
              'settings:manage',
            ],
          },
          {
            name: 'Dispatcher',
            description: 'Order dispatcher',
            isSystem: true,
            permissions: [
              'orders:create',
              'orders:view:all',
              'orders:assign',
              'drivers:view',
            ],
          },
          {
            name: 'Driver',
            description: 'Delivery driver',
            isSystem: true,
            permissions: [
              'orders:view:assigned',
              'orders:update:status',
              'profile:edit',
            ],
          },
        ],
      },
    },
    include: { roles: true },
  });
  console.log('✅ Sample tenant created');

  // Create admin user
  const adminPassword = await bcrypt.hash('Admin123!', 10);
  await prisma.user.upsert({
    where: { email: 'admin@system.com' },
    update: {},
    create: {
      email: 'admin@system.com',
      name: 'System Administrator',
      passwordHash: adminPassword,
      tenantId: adminTenant.id,
      roleId: adminTenant.roles[0].id,
    },
  });
  console.log('✅ Admin user created');

  // Create sample users
  const sampleUsers = [
    {
      email: 'admin@sample.com',
      name: 'Admin User',
      password: 'Admin123!',
      role: 'Admin',
    },
    {
      email: 'dispatcher@sample.com',
      name: 'Dispatch User',
      password: 'Dispatch123!',
      role: 'Dispatcher',
    },
    {
      email: 'driver@sample.com',
      name: 'Driver User',
      password: 'Driver123!',
      role: 'Driver',
    },
  ];

  for (const userData of sampleUsers) {
    const role = sampleTenant.roles.find((r) => r.name === userData.role);
    if (role) {
      const passwordHash = await bcrypt.hash(userData.password, 10);
      await prisma.user.upsert({
        where: { email: userData.email },
        update: {},
        create: {
          email: userData.email,
          name: userData.name,
          passwordHash,
          tenantId: sampleTenant.id,
          roleId: role.id,
        },
      });
      console.log(`✅ User ${userData.email} created`);
    }
  }

  // Create some audit log entries
  await prisma.auditLog.createMany({
    data: [
      {
        action: 'SYSTEM_START',
        status: 'SUCCESS',
        details: { message: 'Database seeded successfully' },
      },
      {
        userId: (
          await prisma.user.findUnique({ where: { email: 'admin@system.com' } })
        )?.id,
        userEmail: 'admin@system.com',
        tenantId: adminTenant.id,
        action: 'SEED_COMPLETED',
        status: 'SUCCESS',
        details: { timestamp: new Date().toISOString() },
      },
    ],
  });
  console.log('✅ Audit logs created');

  console.log('🌱 Database seeding completed successfully!');
}

main()
  .catch((e) => {
    console.error('❌ Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });
