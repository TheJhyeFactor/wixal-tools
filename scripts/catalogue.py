#!/usr/bin/env python3
"""Offline TUF root signing, repository assembly and gated promotion validation.

Private key files must be outside this checkout and output. The root requires
at least two of three separately assigned public keys. No keys are generated
or published by this script, and no repository is uploaded automatically.
"""
import argparse
import hashlib
import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from tuf.api.metadata import Metadata,Root,Targets,Snapshot,Timestamp,TargetFile,MetaFile
from securesystemslib.signer import CryptoSigner,Key

ROOT=Path(__file__).resolve().parents[1]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def expiration(days):return datetime.now(timezone.utc)+timedelta(days=days)
def checked_key(path,output):
    path=Path(path).resolve(strict=True);output=Path(output).resolve()
    if path.is_relative_to(ROOT) or path.is_relative_to(output):raise ValueError('Private keys must remain outside checkout and published output')
    if path.stat().st_mode&0o077:raise ValueError('Private key file must be readable only by its owner')
    return path
def bootstrap(custody,output):
    config=json.loads(Path(custody).read_text());roles=config['roles']
    if set(roles)!={'root','targets','snapshot','timestamp'}:raise ValueError('All four TUF roles require explicit custody')
    root=Root(expires=expiration(365),consistent_snapshot=False)
    for role,entries in roles.items():
        if not isinstance(entries,list) or not entries:raise ValueError('Missing role custody')
        if role=='root' and (len(entries)<3 or len({r['custodian'] for r in entries})<3):raise ValueError('Root needs three independently assigned custodians')
        for entry in entries:
            key=Key.from_dict(entry['keyid'],entry['publicKey']);root.add_key(key,role)
        root.roles[role].threshold=2 if role=='root' else 1
    if len(set(root.roles['root'].keyids))<3:raise ValueError('Root needs three distinct public keys')
    Metadata(root).to_file(str(output))
def sign(metadata_path,root_path,keyid,private_path):
    root=Metadata.from_file(str(root_path));metadata=Metadata.from_file(str(metadata_path))
    role=metadata.signed.type
    if keyid not in root.signed.roles[role].keyids:raise ValueError('Signer is not assigned to this metadata role')
    path=checked_key(private_path,Path(metadata_path).parent)
    signer=CryptoSigner.from_priv_key_uri('file2:'+str(path),root.signed.keys[keyid])
    metadata.sign(signer,append=True);metadata.to_file(str(metadata_path))
def assemble(root_path,catalogue_path,payload_directory,signers_path,output):
    root=Metadata.from_file(str(root_path));root.verify_delegate('root',root)
    if root.signed.is_expired() or root.signed.roles['root'].threshold<2 or len(root.signed.roles['root'].keyids)<3:raise ValueError('Root custody threshold or expiry failed')
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False)
    metadata=output/'metadata';metadata.mkdir();targets=output/'targets';targets.mkdir()
    source=Path(payload_directory).resolve();catalogue=json.loads(Path(catalogue_path).read_text())
    if catalogue.get('schemaVersion')!=1 or not isinstance(catalogue.get('packages'),list):raise ValueError('Invalid catalogue')
    import shutil
    shutil.copy2(root_path,metadata/'root.json')
    for row in catalogue['packages']:
        target=Path(row['target'])
        if target.is_absolute() or '..' in target.parts:raise ValueError('Unsafe payload target')
        path=(source/target).resolve(strict=True)
        if not path.is_relative_to(source) or digest(path)!=row['sha256'] or path.stat().st_size!=row['length']:raise ValueError('Payload identity mismatch')
        destination=targets/target;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
    (targets/'catalogue.json').write_text(json.dumps(catalogue,indent=2)+'\n')
    signers=json.loads(Path(signers_path).read_text())
    def publish(role,signed):
        data=Metadata(signed)
        for keyid,key_path in signers.get(role,{}).items():
            if keyid not in root.signed.roles[role].keyids:raise ValueError('Unexpected role signer')
            path=checked_key(key_path,output)
            data.sign(CryptoSigner.from_priv_key_uri('file2:'+str(path),root.signed.keys[keyid]),append=True)
        root.verify_delegate(role,data);data.to_file(str(metadata/(role+'.json')))
    target_data=Targets(expires=expiration(7))
    for path in sorted(targets.rglob('*')):
        if path.is_file():target_data.targets[str(path.relative_to(targets))]=TargetFile.from_file(str(path.relative_to(targets)),str(path))
    publish('targets',target_data)
    publish('snapshot',Snapshot(expires=expiration(7),meta={'targets.json':MetaFile.from_data(1,(metadata/'targets.json').read_bytes(),['sha256'])}))
    publish('timestamp',Timestamp(expires=expiration(2),snapshot_meta=MetaFile.from_data(1,(metadata/'snapshot.json').read_bytes(),['sha256'])))
def rotation(previous,new):
    before=Metadata.from_file(str(previous));after=Metadata.from_file(str(new))
    if after.signed.version!=before.signed.version+1:raise ValueError('Root rotation must advance one version')
    before.verify_delegate('root',after);after.verify_delegate('root',after)
    if after.signed.roles['root'].threshold<2:raise ValueError('Root threshold must remain at least two')
def promotion(repository,evidence):
    contract=json.loads((ROOT/'contracts/promotion.json').read_text())
    if not contract.get('publicTufCatalogue') or not contract.get('productionTrustedRoot') or contract.get('productionSigningKeys')=='not_configured':raise ValueError('Production promotion is gated: public trust and independent signing custody are not configured')
    root=Metadata.from_file(str(Path(repository)/'metadata/root.json'));root.verify_delegate('root',root)
    if digest(Path(repository)/'metadata/root.json')!=contract['productionTrustedRoot']['sha256']:raise ValueError('Promoted root differs from reviewed contract')
    report=json.loads(Path(evidence).read_text())
    mandatory={r['id'] for r in json.loads((ROOT/'contracts/acceptance-suite.json').read_text())['families'] if r['mandatory']}
    passed={r['id'] for r in report.get('cases',[]) if r.get('status')=='passed'}
    if not mandatory<=passed:raise ValueError('Missing mandatory acceptance: '+','.join(sorted(mandatory-passed)))
    if report.get('status')!='passed':raise ValueError('Acceptance report did not pass')
    return dict(status='ready_for_review',automaticPromotion=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='operation',required=True)
    b=sub.add_parser('bootstrap');b.add_argument('--custody',required=True);b.add_argument('--output',required=True)
    s=sub.add_parser('sign');s.add_argument('--metadata',required=True);s.add_argument('--root',required=True);s.add_argument('--keyid',required=True);s.add_argument('--private-key',required=True)
    a=sub.add_parser('assemble');a.add_argument('--root',required=True);a.add_argument('--catalogue',required=True);a.add_argument('--payloads',required=True);a.add_argument('--signers',required=True);a.add_argument('--output',required=True)
    r=sub.add_parser('verify-rotation');r.add_argument('--previous',required=True);r.add_argument('--new',required=True)
    v=sub.add_parser('verify-promotion');v.add_argument('--repository',required=True);v.add_argument('--evidence',required=True)
    o=p.parse_args()
    if o.operation=='bootstrap':bootstrap(o.custody,o.output)
    elif o.operation=='sign':sign(o.metadata,o.root,o.keyid,o.private_key)
    elif o.operation=='assemble':assemble(o.root,o.catalogue,o.payloads,o.signers,o.output)
    elif o.operation=='verify-rotation':rotation(o.previous,o.new)
    else:print(json.dumps(promotion(o.repository,o.evidence)))
if __name__=='__main__':main()
