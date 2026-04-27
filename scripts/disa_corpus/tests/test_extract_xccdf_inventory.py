import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

mod_path = Path(__file__).resolve().parents[1] / 'extract_xccdf_inventory.py'
spec = importlib.util.spec_from_file_location('extract_xccdf_inventory', mod_path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

XCCDF = '''<?xml version="1.0"?>
<Benchmark id="Example_STIG">
  <title>Example</title>
  <Group id="V-1">
    <Rule id="SV-1" severity="high">
      <version>EX-00-1</version>
      <title>Rule title</title>
      <ident>CCI-000001</ident>
      <check><check-content>run command</check-content></check>
      <fixtext>fix it</fixtext>
    </Rule>
  </Group>
</Benchmark>
'''


class ExtractXccdfInventoryTests(unittest.TestCase):
    def test_extract_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'x.xml'
            p.write_text(XCCDF)
            inv = m.extract(p)
        self.assertEqual(inv['benchmark_id'], 'Example_STIG')
        self.assertEqual(inv['total_rules'], 1)
        self.assertEqual(inv['rules'][0]['vuln_id'], 'V-1')
        self.assertEqual(inv['rules'][0]['stigid'], 'EX-00-1')
        self.assertEqual(inv['rules'][0]['cci'], ['CCI-000001'])

    def test_extract_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'x.zip'
            with zipfile.ZipFile(z, 'w') as archive:
                archive.writestr('U_Example_XCCDF.xml', XCCDF)
            inv = m.extract(z)
        self.assertEqual(inv['source_member'], 'U_Example_XCCDF.xml')
        self.assertEqual(inv['total_rules'], 1)


if __name__ == '__main__':
    unittest.main()
