import en from "../locales/errors/en.json";
import ja from "../locales/errors/ja.json";
import type { Locale } from "./i18n";

export type ErrorCode = keyof typeof en;

export type AppErrorPayload = {
  code: string;
  message?: string;
  params?: Record<string, string>;
};

export type BindingResult<T> =
  | { data: T; error?: never }
  | { data?: never; error: AppErrorPayload };

declare const displayErrorBrand: unique symbol;

export type DisplayError = {
  readonly code: ErrorCode;
  readonly params: Readonly<Record<string, string>>;
  readonly [displayErrorBrand]: true;
};

const messages: Record<Locale, Record<ErrorCode, string>> = { en, ja };
const knownCodes = new Set<ErrorCode>(Object.keys(en) as ErrorCode[]);

export class AppError extends Error {
  readonly payload: AppErrorPayload;

  constructor(payload: AppErrorPayload) {
    super(payload.message ?? payload.code);
    this.name = "AppError";
    this.payload = {
      code: payload.code,
      message: payload.message,
      params: { ...payload.params },
    };
  }
}

export function createAppError(code: ErrorCode, params: Record<string, string> = {}): AppError {
  return new AppError({ code, params });
}

export function toDisplayError(error: unknown): DisplayError {
  const payload = error instanceof AppError ? error.payload : asPayload(error);
  if (!payload || !isErrorCode(payload.code)) {
    return makeDisplayError("internal");
  }
  return makeDisplayError(payload.code, payload.params);
}

export function displayError(code: ErrorCode, params: Record<string, string> = {}): DisplayError {
  return makeDisplayError(code, params);
}

export function formatDisplayError(error: DisplayError, locale: Locale): string {
  const template = messages[locale][error.code] ?? messages[locale].internal;
  return Object.entries(error.params).reduce(
    (text, [name, value]) => text.replaceAll(`{${name}}`, () => value),
    template,
  );
}

export function unwrapBindingResult<T>(result: BindingResult<T>): T {
  if (result.error) {
    throw new AppError(result.error);
  }
  return result.data;
}

function isErrorCode(code: string): code is ErrorCode {
  return knownCodes.has(code as ErrorCode);
}

function asPayload(value: unknown): AppErrorPayload | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as { code?: unknown; params?: unknown };
  if (typeof candidate.code !== "string") return undefined;
  const params =
    candidate.params && typeof candidate.params === "object"
      ? Object.fromEntries(
          Object.entries(candidate.params).filter(
            (entry): entry is [string, string] => typeof entry[1] === "string",
          ),
        )
      : {};
  return { code: candidate.code, params };
}

function makeDisplayError(code: ErrorCode, params: Record<string, string> = {}): DisplayError {
  return {
    code,
    params: { ...params },
  } as DisplayError;
}
