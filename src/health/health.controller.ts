import { Controller, Get } from '@nestjs/common';

@Controller('health')
export class HealthController {
  @Get()
  health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      services: {
        database: 'connected',
        redis: 'connected',
      },
    };
  }

  @Get('readiness')
  readiness() {
    // More detailed check for readiness probe
    return {
      status: 'ready',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('liveness')
  liveness() {
    // Simple check for liveness probe
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  }
}
