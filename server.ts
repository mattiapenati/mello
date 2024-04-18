// @deno-types="./wasm/mello_core.d.ts"
export { CsrfKey, MasterKey } from "./wasm/mello_core.js";

import {
  type Cookie,
  getCookies,
  getSetCookies,
  setCookie,
} from "jsr:@std/http@^0.222.1";
import type {
  FreshContext,
  MiddlewareHandler,
} from "https://deno.land/x/fresh@1.6.8/server.ts";

// @deno-types="./wasm/mello_core.d.ts"
import { type CsrfKey, CsrfToken } from "./wasm/mello_core.js";

/** The default name of the cookie */
const DEFAULT_CSRF_COOKIE_NAME = "csrftoken";
/** Cookie name used to send the token to the client */
const CSRF_COOKIE_NAME = Deno.env.get("CSRF_COOKIE_NAME") ??
  DEFAULT_CSRF_COOKIE_NAME;

/** Middleware that send the CSRF token as cookie
 *
 * @param key Secret key used to sign and verify tokens
 */
export const SendCsrfMiddleware = <State>(
  key: CsrfKey,
): MiddlewareHandler<State> => {
  // check if the request has a valid CSRF token
  const hasCsrfValidToken = (req: Request): boolean => {
    const cookies = getCookies(req.headers);
    const csrfCookie = cookies[CSRF_COOKIE_NAME];
    try {
      CsrfToken.parseFromString(csrfCookie).verify(key);
      return true;
    } catch (err) {
      const path = new URL(req.url).pathname;
      console.error(`[${path}] Failed to parse CSRF token: ${err}`);
      return false;
    }
  };

  // Check if the header `Set-Cookie` for the CSRF token is missing.
  // The header `Set-Cookie` can be set by a nested middleware, this check
  // avoids the replacement by outer middleware.
  const csrfSetCookieMissing = (res: Response): boolean => {
    return getSetCookies(res.headers)
      .find((cookie) => cookie.name === CSRF_COOKIE_NAME) === undefined;
  };

  return async (
    req: Request,
    ctx: FreshContext<State>,
  ) => {
    const res = await ctx.next();

    const shouldSetCookie = ctx.destination === "route" &&
      req.method === "GET" && res.ok && csrfSetCookieMissing(res) &&
      !hasCsrfValidToken(req);
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
