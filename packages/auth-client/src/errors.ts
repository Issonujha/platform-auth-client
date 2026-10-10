/** Error hierarchy for the auth-client. */
export class AuthClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The token is malformed, has an unsupported alg, or failed signature verification. */
export class InvalidTokenError extends AuthClientError {}

/** The token signature was valid but the token is expired (or not yet valid). */
export class TokenExpiredError extends AuthClientError {}
