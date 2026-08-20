import { randomBytes } from 'node:crypto';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
  UsePipes,
} from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { getEnv } from '../../config/env.js';
import { DatabaseService } from '../../infra/db/database.service.js';
import { AuthService, InvalidCredentialsError, WeakPasswordError } from './application/auth.service.js';
import { InvalidRefreshTokenError, RefreshService } from './application/refresh.service.js';
import { InvalidEmailError } from './domain/email.js';
import {
  ACCESS_COOKIE,
  AuthGuard,
  type AuthenticatedRequest,
} from './guards/auth.guard.js';
import { CSRF_COOKIE, CsrfGuard } from './guards/csrf.guard.js';
import { ZodValidationPipe } from './dto/zod-validation.pipe.js';
import {
  type LoginInput,
  type RefreshInput,
  type RegisterInput,
  loginSchema,
  refreshSchema,
  registerSchema,
} from './dto/auth.schemas.js';
import { SessionRepository } from './infra/session.repository.js';

const REFRESH_COOKIE = 'vlos_refresh';

@Controller({ path: 'auth', version: '1' })
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly refresh: RefreshService,
    private readonly sessions: SessionRepository,
    private readonly db: DatabaseService,
  ) {}

  /**
   * 202 sempre, tenha o e-mail sido cadastrado ou nao (item 9).
   * A conclusao do fluxo depende da verificacao de e-mail (Fase 1B).
   */
  @Post('register')
  @HttpCode(HttpStatus.ACCEPTED)
  @UsePipes(new ZodValidationPipe(registerSchema))
  async register(@Body() body: RegisterInput, @Req() req: AuthenticatedRequest): Promise<{ status: string }> {
    try {
      await this.auth.register({
        email: body.email,
        password: body.password,
        displayName: body.displayName,
        signals: signalsOf(req),
      });
    } catch (err) {
      if (err instanceof InvalidEmailError || err instanceof WeakPasswordError) throw err;
      throw err;
    }
    return { status: 'accepted' };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UsePipes(new ZodValidationPipe(loginSchema))
  async login(
    @Body() body: LoginInput,
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<Record<string, unknown>> {
    let issued;
    try {
      issued = await this.auth.login({
        email: body.email,
        password: body.password,
        signals: signalsOf(req),
      });
    } catch (err) {
      if (err instanceof InvalidCredentialsError) throw new UnauthorizedException();
      throw err;
    }

    if (body.transport === 'cookie') {
      setAuthCookies(reply, issued.accessToken, issued.refreshToken, issued.expiresInSeconds);
      return { status: 'ok', expiresIn: issued.expiresInSeconds };
    }

    return {
      accessToken: issued.accessToken,
      refreshToken: issued.refreshToken,
      tokenType: 'Bearer',
      expiresIn: issued.expiresInSeconds,
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @UseGuards(CsrfGuard)
  @UsePipes(new ZodValidationPipe(refreshSchema))
  async rotate(
    @Body() body: RefreshInput,
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<Record<string, unknown>> {
    const fromCookie = (req as { cookies?: Record<string, string | undefined> }).cookies?.[REFRESH_COOKIE];
    const raw = body.refreshToken ?? fromCookie;
    if (!raw) throw new UnauthorizedException();

    let issued;
    try {
      issued = await this.refresh.rotate({ rawToken: raw, signals: signalsOf(req) });
    } catch (err) {
      if (err instanceof InvalidRefreshTokenError) {
        clearAuthCookies(reply);
        throw new UnauthorizedException();
      }
      throw err;
    }

    if (fromCookie && !body.refreshToken) {
      setAuthCookies(reply, issued.accessToken, issued.refreshToken, issued.expiresInSeconds);
      return { status: 'ok', expiresIn: issued.expiresInSeconds };
    }

    return {
      accessToken: issued.accessToken,
      refreshToken: issued.refreshToken,
      tokenType: 'Bearer',
      expiresIn: issued.expiresInSeconds,
    };
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(AuthGuard, CsrfGuard)
  async logout(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    const auth = req.auth!;
    await this.auth.logout({ userId: auth.userId, sessionId: auth.sessionId, signals: signalsOf(req) });
    clearAuthCookies(reply);
  }

  @Post('logout-all')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard, CsrfGuard)
  async logoutAll(
    @Req() req: AuthenticatedRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ revokedSessions: number }> {
    const auth = req.auth!;
    const revoked = await this.auth.logoutAll({ userId: auth.userId, signals: signalsOf(req) });
    clearAuthCookies(reply);
    return { revokedSessions: revoked };
  }

  /**
   * Prova a cadeia inteira: token -> AuthContext -> withUserContext -> RLS.
   * A consulta nao filtra por id; quem filtra e a policy.
   */
  @Get('me')
  @UseGuards(AuthGuard)
  async me(@Req() req: AuthenticatedRequest): Promise<Record<string, unknown>> {
    const auth = req.auth!;
    return this.db.withUserContext(auth.userId, async (tx) => {
      const result = await tx.query<{ id: string; email: string; display_name: string }>(
        `SELECT id, email, display_name FROM identity."user"`,
      );
      const row = result.rows[0];
      if (!row) throw new UnauthorizedException();
      return {
        id: row.id,
        email: row.email,
        displayName: row.display_name,
        sessionId: auth.sessionId,
        amr: auth.amr,
      };
    });
  }

  @Get('sessions')
  @UseGuards(AuthGuard)
  async listSessions(@Req() req: AuthenticatedRequest): Promise<Record<string, unknown>[]> {
    const auth = req.auth!;
    const sessions = await this.sessions.listOwn(auth.userId);
    return sessions.map((s) => ({
      id: s.id,
      amr: s.amr,
      expiresAt: s.expiresAt,
      current: s.id === auth.sessionId,
    }));
  }
}

function signalsOf(req: AuthenticatedRequest): {
  ip?: string | undefined;
  userAgent?: string | undefined;
  requestId?: string | undefined;
} {
  return {
    ip: req.ip,
    userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined,
    requestId: String(req.id),
  };
}

function setAuthCookies(
  reply: FastifyReply,
  accessToken: string,
  refreshToken: string,
  expiresIn: number,
): void {
  const env = getEnv();
  const base = {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: 'lax' as const,
    path: '/api',
    ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
  };

  reply.setCookie(ACCESS_COOKIE, accessToken, { ...base, maxAge: expiresIn });
  reply.setCookie(REFRESH_COOKIE, refreshToken, {
    ...base,
    maxAge: env.REFRESH_TOKEN_TTL_DAYS * 86_400,
  });
  // Legivel pelo JavaScript de proposito: e o par do double-submit.
  reply.setCookie(CSRF_COOKIE, randomBytes(24).toString('base64url'), {
    ...base,
    httpOnly: false,
    maxAge: env.REFRESH_TOKEN_TTL_DAYS * 86_400,
  });
}

function clearAuthCookies(reply: FastifyReply): void {
  for (const name of [ACCESS_COOKIE, REFRESH_COOKIE, CSRF_COOKIE]) {
    reply.clearCookie(name, { path: '/api' });
  }
}
