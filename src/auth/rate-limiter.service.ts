import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  RateLimiterRedis,
  IRateLimiterStoreOptions,
} from 'rate-limiter-flexible';
import Redis from 'ioredis';

export const RATE_LIMITER_SERVICE = 'RATE_LIMITER_SERVICE';

@Injectable()
export class RateLimiterService implements OnModuleDestroy {
  private readonly redis: Redis;
  private readonly loginLimiter: RateLimiterRedis;
  private readonly blacklistLimiter: RateLimiterRedis;

  constructor(private readonly configService: ConfigService) {
    this.redis = new Redis({
      host: this.configService.getOrThrow<string>('REDIS_HOST'),
      port: this.configService.getOrThrow<number>('REDIS_PORT'),
      password: this.configService.get<string>('REDIS_PASSWORD'),
      enableOfflineQueue: false,
    });

    const baseOptions: Partial<IRateLimiterStoreOptions> = {
      storeClient: this.redis,
      // Stays functional if Redis is temporarily unreachable —
      // falls back to in-memory so the app never hard-crashes on a Redis blip.
      insuranceLimiter: undefined,
    };

    // 5 attempts per 15-minute window, per email:tenantId key
    this.loginLimiter = new RateLimiterRedis({
      ...baseOptions,
      keyPrefix: 'rl:login',
      points: 5,
      duration: 15 * 60,
      blockDuration: 15 * 60,
    } as IRateLimiterStoreOptions);

    // Token blacklist: each token is its own key, consumed once,
    // kept alive for the access token's lifetime (15 minutes default).
    this.blacklistLimiter = new RateLimiterRedis({
      ...baseOptions,
      keyPrefix: 'rl:blacklist',
      points: 1,
      duration: 15 * 60,
    } as IRateLimiterStoreOptions);
  }

  /**
   * Consumes one point for the given login key.
   * Throws RateLimiterRes if the limit is already exceeded.
   */
  async consumeLoginAttempt(key: string): Promise<void> {
    await this.loginLimiter.consume(key);
  }

  /**
   * Resets the login attempt counter for the given key on a successful login.
   */
  async resetLoginAttempts(key: string): Promise<void> {
    await this.loginLimiter.delete(key);
  }

  /**
   * Adds a token to the blacklist.
   * @param token  The raw JWT string.
   * @param ttlSeconds  How long until the key expires (should match token expiry).
   */
  async blacklistToken(token: string, ttlSeconds: number): Promise<void> {
    // We set points = 1 and consume it immediately so the key exists.
    // The reward call keeps the TTL aligned with the real token expiry.
    await this.blacklistLimiter.set(token, 0, ttlSeconds);
  }

  /**
   * Returns true if the token has been blacklisted.
   */
  async isTokenBlacklisted(token: string): Promise<boolean> {
    const res = await this.blacklistLimiter.get(token);
    return res !== null;
  }

  onModuleDestroy(): void {
    this.redis.disconnect();
  }
}
