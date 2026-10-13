import Redis from "ioredis";
import { redisConfig } from "./runtime-config";

export const redis = new Redis({
  ...redisConfig(),
  lazyConnect: process.env.REDIS_LAZY_CONNECT === "true",
  connectTimeout: 1_000,
  maxRetriesPerRequest: 1,
});

redis.on("error", () => undefined);
