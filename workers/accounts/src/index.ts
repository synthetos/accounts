/** A1-01 foundation only. No sign-in, session or OIDC endpoints are enabled. */
export default {
  fetch(): Response {
    return new Response('Identity service is not enabled.', {
      status: 503,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'Permissions-Policy': 'serial=(), usb=(), hid=(), bluetooth=()',
      },
    });
  },
};
