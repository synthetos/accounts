# Login navigation regression

This checks the actual compiled Worker and local D1 using Python Playwright and
real headless Chromium. All browser requests, including redirected requests, are
intercepted through CDP; a closed loopback proxy prevents any missed request from
reaching the Internet. The GitHub authorization page is a static stub, and no
GitHub credentials are used. No production origin, database or secret is involved.

Use the pinned Node/pnpm and installed Wrangler/TypeScript test toolchains.
Python dependencies are wheel-only, pinned and hash checked for the CI Linux
Python 3.12 and local macOS ARM Python 3.9 environments:

```sh
python3 -m venv .browser-venv
.browser-venv/bin/python -m pip install --require-hashes --only-binary=:all: -r test/browser/requirements.txt
.browser-venv/bin/python test/browser/licences.py | node test/browser/check-licences.mjs
.browser-venv/bin/python -m playwright install chromium
.browser-venv/bin/python test/browser/run.py
```

The runner starts and disposes its local Worker. It refuses an occupied port and
accepts `--port` or `--executable /path/to/chromium` for local troubleshooting.
`BROWSER_ARTIFACT_DIR=/absolute/path/to/artifact` tests that artifact's modules and
migrations without rebuilding. Without that variable, the fixture builds locally.
The CI `browser` job downloads the build artifact, installs the pinned browser,
and runs these controls without secrets. Attestation and deployment depend on it.
Hosted CI has not been run; local execution does not imply a hosted result.

The three checks distinguish browser behavior from server-side status assertions:

- Actual login HTML: the form sends the exact Origin, receives a 303, and reaches
  the intercepted GitHub authorize URL with no CSP violation or Referer header.
- Change only its form CSP back to `form-action 'self'`: the POST still receives
  a 303, but Chromium blocks the redirect and reports a form-action violation.
- Change only its Referrer-Policy back to `no-referrer`: Chromium sends
  `Origin: null` and the unchanged exact-Origin check refuses the POST with 403.

The test fails if any interception handler fails. The CI browser job uses this same harness.

The harness also checks account forms: actual same-origin POST followed by an
explicit GitHub hyperlink succeeds with self-only form-action; changing the form
document to no-referrer produces Origin:null and a 403. The signed-in browser
fixture is synthetic and belongs only to the loopback test server.

The four Python packages have their installed licence metadata checked through
the same repository policy as npm dependencies. The pinned greenlet and
typing_extensions packages have explicit dev-only Python licence exceptions;
their notices remain in the installed wheels. None enters the Worker artifact.
