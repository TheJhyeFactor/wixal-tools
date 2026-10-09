import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('catalogue',ROOT/'scripts/catalogue.py');catalogue=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalogue)

class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name)
        self.signers=[CryptoSigner.generate_ed25519() for _ in range(3)]
        entries=[dict(custodian='fixture-custodian-'+str(i),keyid=s.public_key.keyid,publicKey=s.public_key.to_dict()) for i,s in enumerate(self.signers)]
        self.custody=dict(roles=dict(root=entries,targets=entries[:1],snapshot=entries[1:2],timestamp=entries[2:]))
        public=self.directory/'public';public.mkdir()
        self.custody_path=self.directory/'custody.json';self.custody_path.write_text(json.dumps(self.custody));self.root=public/'root.json'
        catalogue.bootstrap(self.custody_path,self.root)
        self.private=[]
        for i,s in enumerate(self.signers):
            file=self.directory/f'key-{i}.pem';file.write_bytes(s.private_bytes);file.chmod(0o600);self.private.append(file)
    def tearDown(self):self.temp.cleanup()
    def signed_root(self):
        for i in range(2):catalogue.sign(self.root,self.root,self.signers[i].public_key.keyid,self.private[i])
        root=Metadata.from_file(str(self.root));root.verify_delegate('root',root);return root
    def test_root_needs_distinct_keys_and_custodians(self):
        self.custody['roles']['root']=self.custody['roles']['root'][:1];self.custody_path.write_text(json.dumps(self.custody))
        with self.assertRaisesRegex(ValueError,'three'):catalogue.bootstrap(self.custody_path,self.directory/'bad.json')
    def test_one_signature_cannot_authorize_root(self):
        catalogue.sign(self.root,self.root,self.signers[0].public_key.keyid,self.private[0])
        root=Metadata.from_file(str(self.root))
        with self.assertRaises(Exception):root.verify_delegate('root',root)
        self.signed_root()
    def test_private_key_permissions_are_enforced(self):
        self.private[0].chmod(0o644)
        with self.assertRaisesRegex(ValueError,'owner'):catalogue.sign(self.root,self.root,self.signers[0].public_key.keyid,self.private[0])
    def test_rotation_requires_old_and_new_threshold(self):
        root=self.signed_root();root.signed.version+=1;root.sign(self.signers[0]);root.sign(self.signers[1],append=True)
        path=self.directory/'next-root.json';root.to_file(str(path));catalogue.rotation(self.root,path)
        root.signed.version+=2;root.to_file(str(path))
        with self.assertRaisesRegex(ValueError,'advance'):catalogue.rotation(self.root,path)
    def test_real_metadata_assembly_and_payload_digest_boundary(self):
        self.signed_root();payloads=self.directory/'payloads';payloads.mkdir();(payloads/'tool.tar.gz').write_bytes(b'controlled-test-payload')
        row=dict(target='tool.tar.gz',sha256=catalogue.digest(payloads/'tool.tar.gz'),length=23)
        row['length']=(payloads/'tool.tar.gz').stat().st_size
        path=self.directory/'catalogue.json';path.write_text(json.dumps(dict(schemaVersion=1,packages=[row])))
        signers=self.directory/'signers.json';signers.write_text(json.dumps({role:{self.signers[i].public_key.keyid:str(self.private[i])} for i,role in enumerate(['targets','snapshot','timestamp'])}))
        output=self.directory/'published';catalogue.assemble(self.root,path,payloads,signers,output)
        root=Metadata.from_file(str(self.root))
        for role in ['targets','snapshot','timestamp']:root.verify_delegate(role,Metadata.from_file(str(output/'metadata'/f'{role}.json')))
        updated=self.directory/'updated';catalogue.assemble(self.root,path,payloads,signers,updated,previous=output)
        _,roles,_=catalogue.verify_repository(updated)
        self.assertEqual({r:d.signed.version for r,d in roles.items()},{'targets':2,'snapshot':2,'timestamp':2})
        (updated/'targets/tool.tar.gz').write_bytes(b'changed after signing')
        with self.assertRaises(Exception):catalogue.verify_repository(updated)
        (payloads/'tool.tar.gz').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'identity'):catalogue.assemble(self.root,path,payloads,signers,self.directory/'bad-published')
    def test_production_gate_cannot_be_bypassed_by_candidate(self):
        with self.assertRaisesRegex(ValueError,'gated'):catalogue.promotion(self.directory,self.directory/'evidence.json')
    def test_promotion_requires_exact_tuple_and_hashed_independent_evidence(self):
        evidence=self.directory/'trace.json';evidence.write_text('{"actualEffect":"none"}')
        identity=dict(packageSha256='package',executableSha256='executable',adapter='adapter',helperSha256='helper',architecture='arm64',macOS='27')
        packages=[dict(sha256='package',adapter='adapter',entrypoint='bin/tool',inventory={'bin/tool':'executable'})]
        families=[dict(id='CASE',mandatory=True,evidenceClasses=['L'])]
        report=dict(status='passed',identity=identity,cases=[dict(id='CASE',status='passed',identity=identity,evidenceClasses=['L'],evidence=[dict(path='trace.json',sha256=catalogue.digest(evidence))])])
        catalogue.verify_evidence(report,self.directory,families,packages)
        evidence.write_text('altered')
        with self.assertRaisesRegex(ValueError,'hash'):catalogue.verify_evidence(report,self.directory,families,packages)
        report['cases'][0]['evidence']=[]
        with self.assertRaisesRegex(ValueError,'independent'):catalogue.verify_evidence(report,self.directory,families,packages)
        report['identity']=dict(identity,helperSha256='different')
        with self.assertRaisesRegex(ValueError,'tuple'):catalogue.verify_evidence(report,self.directory,families,packages)
