import { Global, Module } from '@nestjs/common';
import { RedisEventService } from './redis-event.service';

@Global()
@Module({
  providers: [RedisEventService],
  exports: [RedisEventService],
})
export class RedisEventModule {}
