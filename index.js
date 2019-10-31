const BEARER_SCHEME = 'Bearer';
const AUTHORIZATION_HEADER = 'Authorization';
const COOKIE_HEADER = 'Cookie';
const ACCESS_TOKEN_PARAMETER = 'access_token';

/**
 * Extracts a Bearer token from a request object. Will try to extract an "access_token" from: 
 * (1) "Authentication" header with "Bearer" scheme; or 
 * (2) query string; or 
 * (3) request body; or 
 * (4) request cookie (even it is forbidden strictly by RFC).
 *
 * @param {object} requestObject { query, headers, body } A request object including query, headers and body objects.
 * @param {object} requestObject.query A request querystring parsed as an object.
 * @param {object} requestObject.headers A request headers collection parsed as an object.
 * @param {object} requestObject.body A request body parsed as an object.
 * @returns {string|null} An RFC 6750 bearer token extracted from request.
 * @see https://tools.ietf.org/html/rfc6750#section-2 for more information about supported authentication methods
 */
function extractTokenFromRequest({ query, headers, body } = {}, {
  authorizationHeaderKey = AUTHORIZATION_HEADER,
  cookieHeaderKey = COOKIE_HEADER,
} = {}) {
  let cookies;

  const authHeader = headers ? headers[authorizationHeaderKey] : null;
  const cookieHeader = headers ? headers[cookieHeaderKey] : null;
  let fromQuery = query ? query[ACCESS_TOKEN_PARAMETER] : null;
  let fromBody = body ? body[ACCESS_TOKEN_PARAMETER] : null;

  if (authHeader && authHeader.indexOf(`${BEARER_SCHEME} `) !== -1) {
    // HEADER [section 2.1]
    // SHOULD
    // https://tools.ietf.org/html/rfc6750#section-2.1
    return authHeader.split(' ')[1];

  } else if (fromBody) {
    // BODY [section 2.2]
    // SHOULD NOT, only if 2.1 is inaccessible
    // https://tools.ietf.org/html/rfc6750#section-2.2
    // TODO: validate strictly with this method's conditions (verb, content-type, single-part, etc.)
    return fromBody;

  } else if (fromQuery) {
    // QUERY STRING [section 2.3]
    // SHOULD NOT, only if 2.1 is inaccessible and 2.2 is impossible]
    // https://tools.ietf.org/html/rfc6750#section-2.3
    // TODO: validate strictly with this method's conditions (verb, cache-control)
    return fromQuery;

  } else if (cookieHeader) {
    // COOKIE [section 5.3]
    // MUST NOT
    // https://tools.ietf.org/html/rfc6750#section-5.3
    // TODO: disable if some strict validation flag is true
    cookies = cookie.parse(cookieHeader);
    let fromCookie = cookies[ACCESS_TOKEN_PARAMETER];
    if (fromCookie) {
      return fromCookie;
    }
  } else {
    return null;
  }
}

module.exports = {
  BEARER_SCHEME,
  ACCESS_TOKEN_PARAMETER,
  extractTokenFromRequest,
};
