export const CSRF_HEADER_NAME = "x-csrftoken";

const DEFAULT_CSRF_COOKIE_NAME = "csrftoken";

export const csrf_token = (cookieName?: string) => {
  cookieName = cookieName ?? DEFAULT_CSRF_COOKIE_NAME;
  const re = new RegExp(`(?:^| )${cookieName}=(?<token>[^;]*)`);
  const match = document.cookie.match(re);
  return match?.groups?.token ?? "";
};
