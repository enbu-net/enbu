import { m } from "../paraglide/messages";
import { getLocale, type Locale } from "../paraglide/runtime";

type Messages = typeof m;

/** The codes the UI can show, one per error_* message. */
export type ErrorCode = {
  [K in keyof Messages]: K extends `error_${infer Code}` ? Code : never;
}[keyof Messages];

export type AppErrorPayload = {
  code: string;
  message?: string;
  params?: Record<string, string>;
};

declare const displayErrorBrand: unique symbol;

export type DisplayError = {
  readonly code: ErrorCode;
  readonly params: Readonly<Record<string, string>>;
  readonly [displayErrorBrand]: true;
};

const knownCodes = new Set<string>(
  Object.keys(m)
    .filter((key) => key.startsWith("error_"))
    .map((key) => key.slice("error_".length)),
);

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

export function formatDisplayError(error: DisplayError, locale: Locale = getLocale()): string {
  const format = m[`error_${error.code}`] as (
    inputs: Readonly<Record<string, string>>,
    options: { locale: Locale },
  ) => string;
  return format(error.params, { locale });
}

function isErrorCode(code: string): code is ErrorCode {
  return knownCodes.has(code);
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
