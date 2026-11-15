"""Exercise the real account routes with synthetic SQLite data and capture both themes."""
import argparse
import base64
import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--port', type=int, default=18985)
parser.add_argument('--screens', required=True)
parser.add_argument('--executable')
args = parser.parse_args()
screens = Path(args.screens)
screens.mkdir(parents=True, exist_ok=True)
origin = 'https://accounts.example.test'


def local_request(path, method='GET', headers=None, body=None):
    connection = http.client.HTTPConnection('127.0.0.1', args.port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        result = connection.getresponse()
        return result.status, dict(result.getheaders()), result.read()
    finally:
        connection.close()


sessions = json.loads(local_request('/fixture-session')[2])
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, executable_path=args.executable, proxy={'server': 'http://127.0.0.1:1'})
    context = browser.new_context(viewport={'width': 1440, 'height': 1100}, service_workers='block')
    failures = []

    page = context.new_page()
    cdp = context.new_cdp_session(page)

    def intercept(event):
        request = event['request']
        request_id = event['requestId']
        url = urlsplit(request['url'])
        try:
            assert url.scheme == 'https' and url.netloc == 'accounts.example.test', request['url']
            path = url.path + ('?' + url.query if url.query else '')
            status, headers, body = local_request(path, request['method'], request['headers'], request.get('postData'))
            cdp.send('Fetch.fulfillRequest', {'requestId': request_id, 'responseCode': status,
                     'responseHeaders': [{'name': name, 'value': value} for name, value in headers.items()
                                         if name.lower() not in ['connection', 'transfer-encoding', 'content-length']],
                     'body': base64.b64encode(body).decode('ascii')})
        except Exception as error:
            failures.append(str(error))
            cdp.send('Fetch.failRequest', {'requestId': request_id, 'errorReason': 'Failed'})

    cdp.on('Fetch.requestPaused', intercept)
    cdp.send('Fetch.enable', {'patterns': [{'urlPattern': '*', 'requestStage': 'Request'}]})
    context.add_cookies([{'name': '__Host-acct_sid', 'value': sessions['admin'], 'url': origin,
                         'secure': True, 'httpOnly': True, 'sameSite': 'Lax'}])
    page.on('pageerror', lambda error: failures.append(str(error)))
    page.goto(origin + '/admin/people')
    page.wait_for_load_state('networkidle')
    assert page.get_by_role('heading', name='People & access').count() == 1
    assert page.locator('tbody tr').count() == 8
    for theme in ['light', 'dark']:
        page.emulate_media(color_scheme=theme)
        page.screenshot(path=str(screens / ('accounts-people-' + theme + '.png')), full_page=True)
    page.get_by_label('GitHub username', exact=True).fill('@taylor-workshop')
    page.locator('.add-form select').select_option('tester')
    page.get_by_label('Reason', exact=True).fill('Workshop access approved')
    page.get_by_role('button', name='Add person', exact=True).click()
    page.wait_for_load_state('networkidle')
    assert page.locator('tbody th').filter(has_text='@taylor-workshop').count() == 2, (page.url, page.locator('body').inner_text())
    page.get_by_label('Search by GitHub username or ID').fill('89012')
    page.get_by_role('button', name='Search', exact=True).click()
    page.wait_for_load_state('networkidle')
    assert page.locator('.role-form').count() == 1
    page.get_by_label('Role for @taylor-workshop', exact=True).select_option('remove')
    page.get_by_label('Reason for @taylor-workshop', exact=True).fill('Workshop complete')
    page.get_by_role('button', name='Save', exact=True).click()
    page.wait_for_load_state('networkidle')
    assert page.get_by_text('Workshop complete', exact=True).count() == 1
    context.add_cookies([{'name': '__Host-acct_sid', 'value': sessions['moderator'], 'url': origin,
                         'secure': True, 'httpOnly': True, 'sameSite': 'Lax'}])
    page.goto(origin + '/admin/people')
    page.wait_for_load_state('networkidle')
    assert page.locator('form[method="post"]').count() == 0
    assert page.get_by_text('Read-only access. Administrators manage roles.').count() == 1
    page.screenshot(path=str(screens / 'accounts-people-moderator.png'), full_page=True)
    assert not failures, failures
    browser.close()
print('PASS: light/dark screenshots, add, search, remove, audit, moderator read-only (6 browser checks)')
