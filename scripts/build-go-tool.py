#!/usr/bin/env python3
"""Build a pinned standalone Go candidate with vendored source and notices."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TOOLS={'ffuf','nuclei','trivy','osv-scanner'}
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(argv,cwd=None,env=None,timeout=1800):return subprocess.check_output(argv,cwd=cwd,env=env,text=True,timeout=timeout)
def build(tool,output):
    if tool not in TOOLS or platform.system()!='Darwin' or platform.machine()!='arm64':raise ValueError('Supported Go tool and real arm64 macOS builder required')
    recipe_path=ROOT/'recipes'/f'{tool}-darwin-arm64.json';recipe=json.loads(recipe_path.read_text())
    row=next(r for r in json.loads((ROOT/'tools.lock.json').read_text())['tools'] if r['id']==tool)
    if recipe['sourceCommit']!=row['sourceCommit'] or recipe['sourceRepository']!=row['fork']:raise ValueError('Recipe source differs from lock')
    compiler=command(['go','version']).strip()
    if 'go'+recipe['goToolchain']+' ' not in compiler:raise ValueError('Use the pinned Go compiler: '+recipe['goToolchain'])
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='wixal-go-source-') as temp:
        source=Path(temp)/'source';source.mkdir()
        command(['git','init','-q',str(source)]);command(['git','-C',str(source),'remote','add','origin',row['fork']+'.git'])
        command(['git','-C',str(source),'fetch','--depth=1','origin',row['sourceCommit']]);command(['git','-C',str(source),'checkout','--detach','FETCH_HEAD'])
        if command(['git','-C',str(source),'rev-parse','HEAD']).strip()!=row['sourceCommit']:raise ValueError('Wrong source commit')
        for name,expected in recipe['moduleDigests'].items():
            if digest(source/name)!=expected:raise ValueError('Pinned Go module file changed')
        for notice in row['licenseFiles']:
            if digest(source/notice['path'])!=notice['sha256']:raise ValueError('Pinned license changed')
        env=dict(os.environ,GOTOOLCHAIN='local',GOOS='darwin',GOARCH='arm64',CGO_ENABLED='0')
        command(['go','mod','vendor'],source,env)
        (output/'bin').mkdir();binary=output/'bin'/tool
        command(['go','build','-mod=vendor','-trimpath','-buildvcs=false',*(['-ldflags',recipe['ldflags']] if recipe.get('ldflags') else []),'-o',str(binary),recipe['buildPackage']],source,env)
        libraries=command(['/usr/bin/otool','-L',str(binary)],timeout=15)
        if any(not line.strip().startswith(('/usr/lib/','/System/Library/')) for line in libraries.splitlines()[1:]):raise ValueError('Undeclared non-system library')
        if command(['/usr/bin/lipo','-archs',str(binary)],timeout=15).strip()!='arm64':raise ValueError('Wrong executable architecture')
        flags={'ffuf':'-V','nuclei':'-version','trivy':'--version','osv-scanner':'--version'}
        with tempfile.TemporaryDirectory(prefix='wixal-tool-readiness-') as home:
            result=subprocess.run([str(binary),flags[tool]],env={'HOME':home,'PATH':'/usr/bin:/bin','LANG':'en_US.UTF-8'},capture_output=True,text=True,timeout=30)
        if result.returncode:raise ValueError('Candidate version readiness failed')
        version=(result.stdout+result.stderr).strip()
        notices=[]
        for file in sorted(source.rglob('*')):
            if file.is_file() and file.name.lower().startswith(('license','copying','notice')) and file.stat().st_size<1024*1024:
                notices.append('File: '+str(file.relative_to(source))+'\nSHA256: '+digest(file)+'\n'+file.read_text(errors='replace'))
        (output/'THIRD-PARTY-NOTICES.txt').write_text('\n\n'.join(notices))
        for notice in row['licenseFiles']:shutil.copy2(source/notice['path'],output/Path(notice['path']).name)
        with tarfile.open(output/'corresponding-source.tar.gz','w:gz') as archive:
            for file in sorted(source.iterdir()):
                if file.name not in {'.git','.github'}:archive.add(file,arcname=tool+'-source/'+file.name)
        report=dict(schemaVersion=1,tool=tool,sourceRepository=row['fork'],sourceCommit=row['sourceCommit'],
                    recipeSha256=digest(recipe_path),builderSha256=digest(__file__),compiler=compiler,
                    moduleDigests=recipe['moduleDigests'],architecture='arm64',macOS=platform.mac_ver()[0],
                    executableSha256=digest(binary),observedVersionOutput=version,systemLibraries=libraries,
                    correspondingSourceSha256=digest(output/'corresponding-source.tar.gz'),
                    releaseQualification='not_qualified',modelQualification='unevaluated',signing='none')
        (output/'provenance.json').write_text(json.dumps(report,indent=2)+'\n')
        (output/'inventory.json').write_text(json.dumps({str(p.relative_to(output)):digest(p) for p in sorted(output.rglob('*')) if p.is_file()},indent=2)+'\n')
        print(json.dumps(report,indent=2))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--tool',choices=sorted(TOOLS),required=True);p.add_argument('--output',required=True);o=p.parse_args();build(o.tool,o.output)
if __name__=='__main__':main()
