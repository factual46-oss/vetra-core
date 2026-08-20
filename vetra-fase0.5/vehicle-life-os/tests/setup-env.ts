const testJwtKeys = [
  {
    kid: 'vetra-key-2026-01',
    alg: 'EdDSA',
    status: 'active',
    createdAt: '2026-01-01T00:00:00.000Z',
    publicPem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPm1zV1Z6e9U07FvK4a0h8R+x8UjRkZ+m3l7m/QZ+M0Q=\n-----END PUBLIC KEY-----',
    privatePem: '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIP4N1rZzZqI7QpX6qM3q5w4j7GZ6+9t6d5F0j8X4uWq7\n-----END PRIVATE KEY-----',
  },
];

process.env.NODE_ENV = 'test';
process.env.API_PORT = '3000';
process.env.LOG_LEVEL = 'fatal';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgres://vlos_app:vetra_password@127.0.0.1:5432/vetra_test';
process.env.DATABASE_AUTH_URL = process.env.DATABASE_AUTH_URL || 'postgres://vlos_auth:vetra_password@127.0.0.1:5432/vetra_test';
process.env.DATABASE_MIGRATOR_URL = process.env.DATABASE_MIGRATOR_URL || 'postgres://vlos_migrator:vetra_password@127.0.0.1:5432/vetra_test';
process.env.TEST_DATABASE_URL_MIGRATOR = process.env.TEST_DATABASE_URL_MIGRATOR || 'postgres://vlos_migrator:vetra_password@127.0.0.1:5432/vetra_test';
process.env.TEST_DATABASE_URL_APP = process.env.TEST_DATABASE_URL_APP || 'postgres://vlos_app:vetra_password@127.0.0.1:5432/vetra_test';
process.env.TEST_DATABASE_URL_AUTH = process.env.TEST_DATABASE_URL_AUTH || 'postgres://vlos_auth:vetra_password@127.0.0.1:5432/vetra_test';
process.env.REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
process.env.KEK_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
process.env.AUTH_PEPPER = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210';
process.env.COOKIE_SECRET = 'vetra_cookie_secret_dev_key_32bytes';
process.env.CORS_ORIGINS = 'http://localhost:3000';
process.env.TRUSTED_PROXIES = '127.0.0.1';
process.env.JWT_KEYS_JSON = JSON.stringify(testJwtKeys);
process.env.JWT_KEY_SET_JSON = JSON.stringify(testJwtKeys);
