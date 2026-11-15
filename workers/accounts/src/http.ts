export function response(body: string | null, status = 200, extra: HeadersInit = {}, html = false, loginForm = false, formHtml = loginForm): Response {
  const headers = new Headers(extra);
  if (!headers.has('Content-Type')) headers.set('Content-Type', html ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  // Chromium checks the form's redirect chain. Only the login form can navigate to GitHub.
  headers.set('Content-Security-Policy', "default-src 'none'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'self'; form-action 'self'" + (loginForm ? ' https://github.com' : ''));
  headers.set('X-Content-Type-Options', 'nosniff');
  // no-referrer on a form document makes its POST Origin null. Preserve the exact-origin guard.
  headers.set('Referrer-Policy', formHtml ? 'same-origin' : 'no-referrer');
  headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  headers.set('Permissions-Policy', 'serial=(), usb=(), hid=(), bluetooth=(), camera=(), microphone=(), geolocation=(), payment=()');
  headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  headers.set('X-Frame-Options', 'DENY');
  return new Response(body, { status, headers });
}
