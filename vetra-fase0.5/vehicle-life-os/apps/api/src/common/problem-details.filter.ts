import {
  type ArgumentsHost,
  Catch,
  type ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { problemFor, type ProblemOptions } from './problem-details.js';

/** Forma do corpo de erro que o Nest produz. Evita `any` na leitura. */
interface NestErrorBody {
  message?: string | string[];
  errors?: Record<string, string[]>;
}

@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  private readonly logger = new Logger(ProblemDetailsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<FastifyRequest>();
    const reply = ctx.getResponse<FastifyReply>();
    const traceId = String(request.id);

    const status =
      exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;

    const options: ProblemOptions = { instance: request.url, traceId };

    if (exception instanceof HttpException) {
      const response: string | object = exception.getResponse();
      if (typeof response === 'string') {
        options.detail = response;
      } else {
        const body = response as NestErrorBody;
        options.detail = Array.isArray(body.message) ? body.message.join('; ') : body.message;
        options.errors = body.errors;
      }
    }

    if (status >= 500) {
      // A causa completa fica no log (com traceId); o cliente recebe so o traceId.
      this.logger.error({ err: exception, traceId, url: request.url }, 'erro nao tratado');
    }

    void reply
      .status(status)
      .header('content-type', 'application/problem+json; charset=utf-8')
      .send(problemFor(status, options));
  }
}
