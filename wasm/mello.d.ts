/* tslint:disable */
/* eslint-disable */
/**
* Private key used to sign and verify tokens.
*/
export class CsrfKey {
  free(): void;
/**
* Generate a new random key.
* @returns {CsrfKey}
*/
  static generate(): CsrfKey;
/**
* Derive a new key, keys with the same tag are equals.
* @param {string} tag
* @returns {CsrfKey}
*/
  derive(tag: string): CsrfKey;
/**
* Returns a string representing this object.
* @returns {string}
*/
  toString(): string;
/**
* Parses a string containing a CSRF key.
* @param {string} s
* @returns {CsrfKey}
*/
  static parseFromString(s: string): CsrfKey;
}
/**
* CSRF signed token.
*/
export class CsrfToken {
  free(): void;
/**
* Generate a new CSRF random token, signed with the given key.
* @param {CsrfKey} key
* @returns {CsrfToken}
*/
  static generate(key: CsrfKey): CsrfToken;
/**
* Verify the CSRF token with the given key.
* @param {CsrfKey} key
*/
  verify(key: CsrfKey): void;
/**
* Returns a string representing this object.
* @returns {string}
*/
  toString(): string;
/**
* Parses a string containing a CSRF token.
* @param {string} s
* @returns {CsrfToken}
*/
  static parseFromString(s: string): CsrfToken;
}
