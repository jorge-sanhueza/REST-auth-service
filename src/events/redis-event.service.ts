import {
  Injectable,
  OnModuleInit,
  OnModuleDestroy,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { randomUUID } from 'crypto';

export interface AuthEvent<T = Record<string, unknown>> {
  type: string;
  data: T;
  timestamp: Date;
  correlationId: string;
}

@Injectable()
export class RedisEventService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisEventService.name);
  private readonly publisher: Redis;
  private readonly subscriber: Redis;
  private readonly eventPrefix = 'auth:events:';
  private readonly callbacks = new Map<
    string,
    Array<(event: AuthEvent<any>) => void>
  >();

  constructor(private configService: ConfigService) {
    const redisOptions = {
      host: this.configService.get<string>('REDIS_HOST', 'localhost'),
      port: this.configService.get<number>('REDIS_PORT', 6379),
      password: this.configService.get<string>('REDIS_PASSWORD', ''),
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
    };

    this.publisher = new Redis(redisOptions);
    this.subscriber = new Redis(redisOptions);

    this.setupErrorHandling();
  }

  onModuleInit(): void {
    // Single message handler to route messages to registered callbacks
    this.subscriber.on('message', (channel, message) => {
      this.handleIncomingMessage(channel, message);
    });
    this.logger.log('Redis Event Service Initialized');
  }

  private setupErrorHandling() {
    this.publisher.on('error', (err) =>
      this.logger.error('Redis Publisher Error', err),
    );
    this.subscriber.on('error', (err) =>
      this.logger.error('Redis Subscriber Error', err),
    );
  }

  async onModuleDestroy() {
    await Promise.all([this.publisher.quit(), this.subscriber.quit()]);
    this.logger.log('Redis connections closed');
  }

  async emit<T>(
    eventType: string,
    data: T,
    correlationId?: string,
  ): Promise<string> {
    const cid = correlationId || randomUUID();
    const event: AuthEvent<T> = {
      type: eventType,
      data,
      timestamp: new Date(),
      correlationId: cid,
    };

    const message = JSON.stringify(event);
    await Promise.all([
      this.publisher.publish(`${this.eventPrefix}${eventType}`, message),
      this.publisher.publish(`${this.eventPrefix}all`, message),
    ]);

    return cid;
  }

  async subscribe<T>(
    eventType: string,
    callback: (event: AuthEvent<T>) => void,
  ) {
    const channel = `${this.eventPrefix}${eventType}`;

    // Register callback in internal map
    const listeners = this.callbacks.get(channel) || [];
    listeners.push(callback);
    this.callbacks.set(channel, listeners);

    await this.subscriber.subscribe(channel);
    this.logger.log(`Subscribed to: ${eventType}`);
  }

  async unsubscribe(
    eventType: string,
    callback?: (event: AuthEvent<any>) => void,
  ) {
    const channel = `${this.eventPrefix}${eventType}`;

    if (callback) {
      // Remove specific callback
      const listeners = this.callbacks.get(channel) || [];
      const filtered = listeners.filter((cb) => cb !== callback);

      if (filtered.length === 0) {
        this.callbacks.delete(channel);
        await this.subscriber.unsubscribe(channel);
      } else {
        this.callbacks.set(channel, filtered);
      }
    } else {
      // Remove all callbacks for this channel
      this.callbacks.delete(channel);
      await this.subscriber.unsubscribe(channel);
    }

    this.logger.log(`Unsubscribed from: ${eventType}`);
  }

  async unsubscribeFromAll() {
    // Clear all callbacks
    this.callbacks.clear();

    // Unsubscribe from all channels
    await this.subscriber.unsubscribe();
    this.logger.log('Unsubscribed from all channels');
  }

  private handleIncomingMessage(channel: string, message: string) {
    try {
      const event = JSON.parse(message) as AuthEvent<unknown>;
      const listeners = this.callbacks.get(channel);
      if (listeners) {
        listeners.forEach((cb) => cb(event));
      }
    } catch (error) {
      this.logger.error(
        `Failed to parse event: ${message}`,
        error instanceof Error ? error.stack : error,
      );
    }
  }

  async getRecentEvents<T>(
    eventType: string,
    limit = 100,
  ): Promise<AuthEvent<T>[]> {
    const pattern = `${this.eventPrefix}history:${eventType}:*`;
    const keys = await this.publisher.keys(pattern);
    const sortedKeys = keys.sort().reverse().slice(0, limit);

    if (sortedKeys.length === 0) return [];

    const results = await this.publisher.mget(...sortedKeys);
    return results
      .filter((data): data is string => !!data)
      .map((data) => JSON.parse(data) as AuthEvent<T>);
  }
}
