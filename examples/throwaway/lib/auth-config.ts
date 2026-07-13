export const SESSION_COOKIE = "throwaway_session";
export const DEFAULT_RETURN_TO = "/app/dashboard";
export const PROTECTED_PATHS = ["/app/:path*"];

// Optional branded error page. Must stay OUT of PROTECTED_PATHS.
export const AUTH_ERROR_PATH = "/auth/error";
