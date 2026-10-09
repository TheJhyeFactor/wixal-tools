#!/usr/bin/env python3
"""Validate source pins and candidate contracts without granting release approval."""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {'rustscan', 'nmap', 'ffuf', 'nuclei', 'wireshark', 'trivy',
            'osv-scanner', 'testssl', 'mitmproxy', 'zap', 'metasploit'}

def validate(root=ROOT):
    lock = json.loads((root / 'tools.lock.json').read_text())
    if lock['schemaVersion'] != 1 or lock['productionCatalogue'] is not None:
        raise ValueError('Source setup must not advertise a production catalogue')
    rows = lock['tools']
    if len(rows) != len(EXPECTED) or {r['id'] for r in rows} != EXPECTED:
        raise ValueError('Catalogue must contain the eleven existing tools once each')
    for row in rows:
        if not re.fullmatch(r'[0-9a-f]{40}', row['sourceCommit']):
            raise ValueError('Every source needs an exact commit')
        if not row['fork'].startswith('https://github.com/TheJhyeFactor/'):
            raise ValueError('Fork must belong to the configured owner')
        if row['managedRelease'] != 'not_qualified' or row['modelQualification'] != 'unevaluated':
            raise ValueError('Source forks cannot qualify packages or models')
        if row['forkActionsEnabled'] is not False:
            raise ValueError('Inherited fork workflows must stay disabled')
        if not row['licenseFiles']:
            raise ValueError('Record pinned upstream license files for ' + row['id'])
        for item in row['licenseFiles']:
            if not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
                raise ValueError('License file digest missing')
            if '/' + row['sourceCommit'] + '/' not in item['url']:
                raise ValueError('License reference must be pinned')
        if row.get('recipe'):
            recipe = json.loads((root / row['recipe']).read_text())
            if recipe['sourceCommit'] != row['sourceCommit'] or recipe['sourceRepository'] != row['fork']:
                raise ValueError('Recipe must match source lock')
            if recipe['distribution'] != 'candidate_only' or recipe['signing'] != 'none':
                raise ValueError('Candidate build must not claim release signing')
            if recipe.get('profile')=='go-single-binary-v1':
                if set(recipe['moduleDigests'])!={'go.mod','go.sum'} or any(not re.fullmatch(r'[0-9a-f]{64}',v) for v in recipe['moduleDigests'].values()):raise ValueError('Go module and dependency checksums must be pinned')
            elif not re.fullmatch(r'[0-9a-f]{64}', recipe['cargoLockSha256']):
                raise ValueError('Cargo.lock must be pinned')
    suite = json.loads((root / 'contracts/acceptance-suite.json').read_text())
    # Use the application-owned acceptance contract verbatim, including its gates.
    cases = suite['families']
    if len(cases) != 104 or len({case['id'] for case in cases}) != 104 or not all(case['mandatory'] for case in cases) or suite['status'] != 'not_qualified':
        raise ValueError('Expected all 104 acceptance families')
    print(json.dumps(dict(status='passed', sourcePins=len(rows), acceptanceFamilies=len(cases),
                          releaseQualification='not_qualified')))
    return lock

def live(root=ROOT):
    import subprocess
    lock = validate(root)
    def api(path):
        return json.loads(subprocess.check_output(['gh', 'api', path], text=True))
    for row in lock['tools']:
        repo = row['fork'].removeprefix('https://github.com/')
        upstream = row['upstream'].removeprefix('https://github.com/')
        info = api('repos/' + repo)
        if not info['fork'] or info['parent']['full_name'].lower() != upstream.lower():
            raise ValueError('Fork provenance differs for ' + row['id'])
        if api('repos/' + repo + '/actions/permissions')['enabled']:
            raise ValueError('Inherited workflows enabled for ' + row['id'])
        if api('repos/' + repo + '/commits/' + row['sourceCommit'])['sha'] != row['sourceCommit']:
            raise ValueError('Pinned commit unavailable')
    print('Live fork provenance, source commits and disabled Actions verified for all eleven tools')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    (live if args.live else validate)()
