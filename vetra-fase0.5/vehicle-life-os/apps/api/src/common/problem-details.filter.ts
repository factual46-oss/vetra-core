import {
  ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { problemFor } from './problem-details.js';

@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  private readonly logger = new Logger(ProblemDetailsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<FastifyRequest>();
    const reply = ctx.getResponse<FastifyReply>();
    const traceId = String(request.id ?? '');

    const status =
      exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

    let detail: string | undefined;
    let errors: Record<string, string[]> | undefined;

    if (exception instanceof HttpException) {
      const response = exception.getResponse();
      if (typeof response === 'string') detail = response;
      else if (response && typeof response === 'object') {
        const body = response as { message?: unknown; errors?: Record<string, string[]> };
        detail = Array.isArray(body.message) ? body.message.join('; ') : (body.message as string);
        errors = body.errors;
      }
    }

    if (status >= 500) {
      // A causa completa fica no log (com traceId); o cliente recebe so o traceId.
      this.logger.error({ err: exception, traceId, url: request.url }, 'erro nao tratado');
    }

    void reply
      .status(status)
      .header('content-type', 'application/problem+json; charset=utf-8')
      .send(problemFor(status, { detail, instance: request.url, traceId, ...(errors ? { errors } : {}) }));
  }
}
