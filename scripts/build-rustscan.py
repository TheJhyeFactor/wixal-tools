#!/usr/bin/env python3
"""Build an unsigned RustScan candidate from pinned, vendored source on arm64 macOS."""
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(argv, cwd=None, timeout=900):
    return subprocess.check_output(argv, cwd=cwd, stderr=None, text=True, timeout=timeout)

def main():
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        raise ValueError('This recipe requires a real arm64 macOS builder')
    recipe_path = ROOT / 'recipes/rustscan-darwin-arm64.json'
    recipe = json.loads(recipe_path.read_text())
    lock = json.loads((ROOT / 'tools.lock.json').read_text())
    row = next(r for r in lock['tools'] if r['id'] == 'rustscan')
    if recipe['sourceCommit'] != row['sourceCommit'] or recipe['sourceRepository'] != row['fork']:
        raise ValueError('Source recipe does not match lock')
    output = ROOT / 'artifacts/rustscan-darwin-arm64'
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='wixal-source-') as directory:
        source = Path(directory) / 'source'; source.mkdir()
        command(['git', 'init', '-q', str(source)])
        command(['git', '-C', str(source), 'remote', 'add', 'origin', row['fork'] + '.git'])
        command(['git', '-C', str(source), 'fetch', '--depth=1', 'origin', row['sourceCommit']])
        command(['git', '-C', str(source), 'checkout', '--detach', 'FETCH_HEAD'])
        if command(['git', '-C', str(source), 'rev-parse', 'HEAD']).strip() != row['sourceCommit']:
            raise ValueError('Unexpected source commit')
        if digest(source / 'Cargo.lock') != recipe['cargoLockSha256']:
            raise ValueError('Cargo dependency lock changed')
        for notice in row['licenseFiles']:
            if digest(source / notice['path']) != notice['sha256']:
                raise ValueError('Pinned upstream license changed')
        command(['rustup', 'toolchain', 'install', recipe['rustToolchain'], '--profile', 'minimal'])
        command(['rustup', 'target', 'add', '--toolchain', recipe['rustToolchain'], recipe['target']])
        cargo = ['cargo', '+' + recipe['rustToolchain']]
        vendor_config = command(cargo + ['vendor', '--locked', '--versioned-dirs', 'vendor'], cwd=source)
        (source / '.cargo').mkdir(exist_ok=True)
        (source / '.cargo/config.toml').write_text(vendor_config)
        command(recipe['buildCommand'], cwd=source)
        binary = source / 'target' / recipe['target'] / 'release/rustscan'
        version = command([str(binary), '--version'], timeout=15).strip()
        if version != recipe['expectedCliVersion']:
            raise ValueError('Observed CLI identity differs: ' + version)
        architecture = command(['/usr/bin/lipo', '-archs', str(binary)], timeout=15).strip()
        if architecture != 'arm64':
            raise ValueError('Unexpected executable architecture')
        libraries = command(['/usr/bin/otool', '-L', str(binary)], timeout=15)
        for line in libraries.splitlines()[1:]:
            name = line.strip().split(' ', 1)[0]
            if not name.startswith(('/usr/lib/', '/System/Library/')):
                raise ValueError('Unexpected runtime dependency: ' + name)
        # A real listener and a held closed port give an independent discovery oracle.
        with socket.socket() as listener, socket.socket() as closed:
            listener.bind(('127.0.0.1', 0)); listener.listen()
            closed.bind(('127.0.0.1', 0))
            open_port = listener.getsockname()[1]; closed_port = closed.getsockname()[1]
            config = source / 'empty-rustscan.toml'; config.write_text('')
            env = {k:v for k,v in os.environ.items() if not k.startswith(('RUSTSCAN', 'RUST_LOG'))}
            result = subprocess.run([str(binary), '--config-path', str(config), '--no-config', '--scripts', 'none',
                                     '--greppable', '--no-banner', '--addresses', '127.0.0.1',
                                     '--ports', str(open_port)+','+str(closed_port), '--batch-size', '32',
                                     '--timeout', '1000'], capture_output=True, text=True,
                                    env=env, cwd=source, timeout=30)
            expected = '127.0.0.1 -> [' + str(open_port) + ']'
            if result.returncode or expected not in result.stdout:
                raise ValueError('Real listener discovery failed: ' + result.stdout + result.stderr)
        (output / 'bin').mkdir(); shutil.copy2(binary, output / 'bin/rustscan')
        for notice in row['licenseFiles']:
            shutil.copy2(source / notice['path'], output / notice['path'])
        with tarfile.open(output / 'corresponding-source.tar.gz', 'w:gz') as archive:
            for item in sorted(source.iterdir()):
                if item.name not in {'.git', '.github', 'target', 'empty-rustscan.toml'}:
                    archive.add(item, arcname='rustscan-source/' + item.name)
        provenance = dict(schemaVersion=1,tool='rustscan',sourceRepository=row['fork'],
                          upstream=row['upstream'],sourceCommit=row['sourceCommit'],
                          cargoLockSha256=recipe['cargoLockSha256'],recipeSha256=digest(recipe_path),
                          builderSha256=digest(__file__),rustc=command(['rustc','+'+recipe['rustToolchain'],'--version']).strip(),
                          cliVersion=version,architecture=architecture,systemLibraries=libraries,
                          macOS=platform.mac_ver()[0],createdAt=datetime.now(timezone.utc).isoformat(),
                          executableSha256=digest(output/'bin/rustscan'),
                          correspondingSourceSha256=digest(output/'corresponding-source.tar.gz'),
                          smoke=dict(status='passed',oracle='real loopback listener and held closed port',
                                     stdoutSha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                                     stderrSha256=hashlib.sha256(result.stderr.encode()).hexdigest()),
                          signing='none',releaseQualification='not_qualified',modelQualification='unevaluated',
                          reproducibility='single_build_only')
        (output/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
        (output/'NOTICE.md').write_text('Unsigned build candidate. No Wixal managed release or model qualification.\nUpstream and vendored dependency licenses are retained in corresponding-source.tar.gz.\n')
        inventory={str(p.relative_to(output)):digest(p) for p in sorted(output.rglob('*')) if p.is_file()}
        (output/'inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
        print(json.dumps(provenance,indent=2))

if __name__ == '__main__': main()
