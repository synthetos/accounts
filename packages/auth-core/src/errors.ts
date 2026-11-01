export type AuthErrorCode = 'invalid_input' | 'invalid_cookie' | 'csrf_denied' | 'invalid_token';

/** Public errors deliberately contain no tokens, claims, cookie values or keys. */
export class AuthError extends Error {
  readonly code: AuthErrorCode;
  constructor(code: AuthErrorCode) {
    super(code);
    this.code = code;
    this.name = 'AuthError';
  }
}

export function requireAuth(condition: unknown, code: AuthErrorCode): asserts condition {
  if (!condition) throw new AuthError(code);
}
