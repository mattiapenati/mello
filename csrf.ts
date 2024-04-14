import { type Cookie, getCookies, setCookie } from "@std/http/cookie";
import type { FreshContext, MiddlewareHandler } from "$fresh/server.ts";

// @deno-types="./wasm/mello.d.ts"
import { type CsrfKey, CsrfToken } from "./wasm/mello.js";

/** The default name of the cookie */
const DEFAULT_CSRF_COOKIE_NAME = "csrftoken";
/** Cookie name used to send the token to the client */
const CSRF_COOKIE_NAME = Deno.env.get("CSRF_COOKIE_NAME") ??
  DEFAULT_CSRF_COOKIE_NAME;

/** The default name of the header */
const DEFAULT_CSRF_HEADER_NAME = "x-csrftoken";
/** Header used to send the token to the server */
export const CSRF_HEADER_NAME = Deno.env.get("CSRF_HEADER_NAME") ??
  DEFAULT_CSRF_HEADER_NAME;

/** Middleware that send the CSRF token as cookie
 *
 * @param key Secret key used to sign and verify tokens
 */
export const SendCsrfMiddleware = <State>(
  key: CsrfKey,
): MiddlewareHandler<State> => {
  const hasCsrfValidToken = (req: Request): boolean => {
    const cookies = getCookies(req.headers);
    const csrfCookie = cookies[CSRF_COOKIE_NAME];
    try {
      CsrfToken.parseFromString(csrfCookie).verify(key);
      return true;
    } catch (err) {
      console.error(`Failed to parse CSRF token: ${err}`);
      return false;
    }
  };

  return async (
    req: Request,
    ctx: FreshContext<State>,
  ) => {
    const res = await ctx.next();

    const shouldSetCookie = ctx.destination === "route" &&
      req.method === "GET" && res.ok && !hasCsrfValidToken(req);
    if (shouldSetCookie) {
      const cookie: Cookie = {
        name: CSRF_COOKIE_NAME,
        value: CsrfToken.generate(key).toString(),
        sameSite: "Strict",
        secure: true,
        httpOnly: false,
        path: "/",
      };
      setCookie(res.headers, cookie);
    }

    return res;
  };
};
