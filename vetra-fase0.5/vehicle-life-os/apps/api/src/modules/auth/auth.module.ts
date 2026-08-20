import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller.js';
import { AuthService } from './application/auth.service.js';
import { RefreshService } from './application/refresh.service.js';
import { AuthDatabaseService } from './infra/auth-database.service.js';
import { AuthAuditService } from './infra/auth-audit.service.js';
import { CredentialRepository } from './infra/credential.repository.js';
import { JwtService } from './infra/jwt.service.js';
import { PasswordHasherService } from './infra/password-hasher.service.js';
import { RateLimitService } from './infra/rate-limit.service.js';
import { RefreshTokenRepository } from './infra/refresh-token.repository.js';
import { SessionRepository } from './infra/session.repository.js';
import { AuthGuard } from './guards/auth.guard.js';
import { CsrfGuard } from './guards/csrf.guard.js';

@Module({
  controllers: [AuthController],
  providers: [
    AuthDatabaseService,
    AuthAuditService,
    AuthService,
    RefreshService,
    CredentialRepository,
    JwtService,
    PasswordHasherService,
    RateLimitService,
    RefreshTokenRepository,
    SessionRepository,
    AuthGuard,
    CsrfGuard,
  ],
  exports: [AuthGuard, SessionRepository],
})
export class AuthModule {}
