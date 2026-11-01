"""Real Chromium form-navigation regression; CDP intercepts every request including redirects."""
import argparse
import base64
import http.client
import json
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=18983)
parser.add_argument('--executable', help='Optional installed Chromium binary; defaults to Playwright Chromium')
args = parser.parse_args()
origin = 'https://accounts.example.test'


def exercise(browser, control):
    context = browser.new_context(service_workers='block')
    account_case = control.startswith('account-')
    if account_case:
        context.add_cookies([{'name':'__Host-acct_sid','value':base64.urlsafe_b64encode(bytes([9])*32).decode().rstrip('='),
                             'url':origin,'secure':True,'httpOnly':True,'sameSite':'Lax'}])
    page = context.new_page()
    violations, destinations, requests, handler_errors = [], [], [], []
    page.on('console', lambda message: violations.append(message.text) if 'form-action' in message.text else None)
    cdp = context.new_cdp_session(page)

    def fulfill(request_id, status, headers, body):
        cdp.send('Fetch.fulfillRequest', {'requestId': request_id, 'responseCode': status,
                 'responseHeaders': [{'name': name, 'value': value} for name, value in headers],
                 'body': base64.b64encode(body).decode('ascii')})

    def intercept(event):
        request = event['request']
        request_id = event['requestId']
        parsed = urlsplit(request['url'])
        try:
            if parsed.scheme == 'https' and parsed.netloc == 'github.com' and parsed.path == '/login/oauth/authorize':
                assert not any(name.lower() == 'referer' for name in request['headers']), 'Referrer leaked to GitHub'
                destinations.append(request['url'])
                fulfill(request_id, 200, [('Content-Type', 'text/html')], b'<title>Stub GitHub authorization</title><p>GitHub destination reached</p>')
                return
            if not request['url'].startswith(origin + '/'):
                cdp.send('Fetch.failRequest', {'requestId': request_id, 'errorReason': 'BlockedByClient'})
                return
            connection = http.client.HTTPConnection('127.0.0.1', args.port, timeout=15)
            try:
                connection.request(request['method'], parsed.path + ('?' + parsed.query if parsed.query else ''),
                                   body=request.get('postData'), headers=request['headers'])
                result = connection.getresponse()
                incoming = {name.lower(): value for name, value in request['headers'].items()}
                requests.append({'method': request['method'], 'path': parsed.path, 'status': result.status,
                                 'origin': incoming.get('origin'), 'has_cookie': 'cookie' in incoming})
                headers = [(name.lower(), value) for name, value in result.getheaders()
                           if name.lower() not in ['connection', 'transfer-encoding', 'content-length']]
                if request['method'] == 'GET' and parsed.path == ('/account' if account_case else '/login'):
                    if account_case:
                        actual_headers = dict(headers)
                        assert actual_headers['referrer-policy'] == 'same-origin'
                        assert actual_headers['content-security-policy'].endswith("form-action 'self'")
                    if control == 'self-only':
                        headers = [(name, value.replace("form-action 'self' https://github.com", "form-action 'self'"))
                                   if name == 'content-security-policy' else (name, value) for name, value in headers]
                    elif control in ['no-referrer','account-no-referrer']:
                        headers = [(name, 'no-referrer' if name == 'referrer-policy' else value) for name, value in headers]
                fulfill(request_id, result.status, headers, result.read())
            finally:
                connection.close()
        except Exception as error:
            handler_errors.append(str(error))
            cdp.send('Fetch.failRequest', {'requestId': request_id, 'errorReason': 'Failed'})

    cdp.on('Fetch.requestPaused', intercept)
    cdp.send('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
    try:
        page.goto(origin + ('/account' if account_case else '/login'))
        page.wait_for_load_state('networkidle')
        button = page.get_by_role('button', name='Verify with GitHub' if account_case else 'Sign in with GitHub')
        assert button.count() == 1
        button.click()
        if control == 'account-actual':
            page.get_by_role('link',name='Continue to GitHub').click()
        navigated = True
        try:
            page.wait_for_url('https://github.com/login/oauth/authorize?**', timeout=3000)
        except PlaywrightTimeout:
            navigated = False
        assert not handler_errors, handler_errors
        posts = [request for request in requests if request['method'] == 'POST']
        assert len(posts) == 1, requests
        if control == 'self-only':
            assert posts[0]['status'] == 303 and posts[0]['origin'] == origin, posts
            assert not navigated and not destinations, 'Restricted policy unexpectedly allowed GitHub navigation'
            assert violations, 'No CSP form-action violation observed'
        elif control in ['no-referrer','account-no-referrer']:
            assert posts[0]['status'] == 403 and posts[0]['origin'] == 'null', posts
            assert not navigated and not destinations
            assert not violations, violations
        else:
            assert posts[0]['status'] == (200 if account_case else 303) and posts[0]['origin'] == origin, posts
            assert navigated and len(destinations) == 1, {'requests': requests, 'url': page.url, 'violations': violations}
            assert not violations, violations
            assert page.title() == 'Stub GitHub authorization'
        print(json.dumps({'control': control, 'navigation_allowed': navigated, 'post_status': posts[0]['status'],
                          'post_origin': posts[0]['origin'], 'form_action_violations': len(violations),
                          'external_requests_sent': 0}))
    finally:
        context.close()


with sync_playwright() as playwright:
    # Any request not intercepted by CDP fails at a closed loopback proxy; it cannot reach the Internet.
    browser = playwright.chromium.launch(headless=True, executable_path=args.executable,
                                        proxy={'server': 'http://127.0.0.1:1'})
    try:
        print(json.dumps({'chromium': browser.version}))
        for control in ['actual', 'self-only', 'no-referrer', 'account-actual', 'account-no-referrer']:
            exercise(browser, control)
    finally:
        browser.close()
