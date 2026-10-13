import { cors } from "@elysiajs/cors";
import { Elysia } from "elysia";
import { createIdentityApp } from "./app";
import { loadIdentityConfig } from "./config";
import { VaultTransitJwtSigner } from "./vault/transit-jwt-signer";
import { httpConfig, readVaultToken } from "./runtime-config";
import pool from "./pg-connector";
import { redis } from "./redis";
import { PostgresIdentityRepository } from "./repository/postgres-identity-repository";
import { RedisIdentityTransientStore } from "./store/redis-transient-store";
import { rateLimiter } from "./rate-limit";

const config = loadIdentityConfig();
const signer = new VaultTransitJwtSigner({
  address: config.vault.address,
  mount: config.vault.transitMount,
  keyName: config.vault.transitKey,
  metadataCacheSeconds: config.vault.keyMetadataCacheSeconds,
  token: readVaultToken,
});
const repository = new PostgresIdentityRepository(pool);
const store = new RedisIdentityTransientStore(redis);

new Elysia()
  .use(cors({
    origin: httpConfig().corsAllowedOrigins,
    credentials: true,
    allowedHeaders: ["content-type", "authorization"],
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
  }))
  .onBeforeHandle(rateLimiter)
  .use(createIdentityApp({ config, signer, repository, store }))
  .listen({ port: config.port });

console.log(`Identity service listening at ${config.issuer}`);

