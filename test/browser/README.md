# Login navigation regression

This checks the actual compiled Worker and local D1 using Python Playwright and
real headless Chromium. All browser requests, including redirected requests, are
intercepted through CDP; a closed loopback proxy prevents any missed request from
reaching the Internet. The GitHub authorization page is a static stub, and no
GitHub credentials are used. No production origin, database or secret is involved.

Use the repository's pinned Node/pnpm and installed Wrangler/TypeScript test
toolchains. In a separate Python virtual environment, install `playwright==1.55.0`
and its Chromium browser (`python -m playwright install chromium`). The test also
accepts `--executable /path/to/chromium` for an existing browser; the validated
local run used Chromium 156.0.8078.4.

From the repository root, start the fixture in one terminal:

```sh
node test/browser/login-server.mjs
```

Run the test from another terminal using that virtual environment:

```sh
python test/browser/login_csp.py
```

Stop the fixture with Ctrl-C. It listens only on 127.0.0.1:18983. A different port
can be selected with `PORT` for the server and `--port` for the Python script.

The three checks distinguish browser behavior from server-side status assertions:

- Actual login HTML: the form sends the exact Origin, receives a 303, and reaches
  the intercepted GitHub authorize URL with no CSP violation or Referer header.
- Change only its form CSP back to `form-action 'self'`: the POST still receives
  a 303, but Chromium blocks the redirect and reports a form-action violation.
- Change only its Referrer-Policy back to `no-referrer`: Chromium sends
  `Origin: null` and the unchanged exact-Origin check refuses the POST with 403.

The test fails if any interception handler fails. This browser check is a local
acceptance test; it is not yet wired into hosted CI.

The harness also checks account forms: actual same-origin POST followed by an
explicit GitHub hyperlink succeeds with self-only form-action; changing the form
document to no-referrer produces Origin:null and a 403. The signed-in browser
fixture is synthetic and belongs only to the loopback test server.
