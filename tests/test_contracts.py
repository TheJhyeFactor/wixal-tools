import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('contracts',ROOT/'scripts/validate.py')
contracts=importlib.util.module_from_spec(spec);spec.loader.exec_module(contracts)

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        for name in ('tools.lock.json','recipes','contracts'):
            source=ROOT/name;dest=self.root/name
            if source.is_dir():shutil.copytree(source,dest)
            else:shutil.copy2(source,dest)
    def tearDown(self):self.temp.cleanup()
    def mutate(self,change):
        path=self.root/'tools.lock.json';data=json.loads(path.read_text());change(data);path.write_text(json.dumps(data))
    def test_exact_source_contract(self):contracts.validate(self.root)
    def test_floating_source_rejected(self):
        self.mutate(lambda d:d['tools'][0].update(sourceCommit='master'))
        with self.assertRaisesRegex(ValueError,'exact commit'):contracts.validate(self.root)
    def test_fork_cannot_become_qualification(self):
        self.mutate(lambda d:d['tools'][0].update(managedRelease='qualified'))
        with self.assertRaisesRegex(ValueError,'cannot qualify'):contracts.validate(self.root)
    def test_production_endpoint_requires_separate_contract(self):
        self.mutate(lambda d:d.update(productionCatalogue='https://example.invalid'))
        with self.assertRaisesRegex(ValueError,'production catalogue'):contracts.validate(self.root)
    def test_recipe_cannot_change_source(self):
        path=self.root/'recipes/rustscan-darwin-arm64.json';data=json.loads(path.read_text());data['sourceCommit']='0'*40;path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'match source'):contracts.validate(self.root)
    def test_missing_acceptance_gate_rejected(self):
        path=self.root/'contracts/acceptance-suite.json';data=json.loads(path.read_text());data['families'].pop();path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'104 acceptance'):contracts.validate(self.root)

if __name__=='__main__':unittest.main()
