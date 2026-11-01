"""Emit installed browser-tool versions/licences for the repository's licence gate."""
from importlib.metadata import metadata
import json

packages = []
for name in ['playwright', 'pyee', 'greenlet', 'typing_extensions']:
    info = metadata(name)
    packages.append({'name': 'python:' + name, 'version': info['Version'],
                     'licence': info.get('License-Expression') or info.get('License'), 'scope': 'dev'})
print(json.dumps(packages))
