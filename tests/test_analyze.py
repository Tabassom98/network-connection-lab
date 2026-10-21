import json
from pathlib import Path
import tempfile
import unittest
from analyze import analyze,load

ROOT=Path(__file__).resolve().parents[1]
def row(i,t=0,port=80,src='192.0.2.1',dst='198.51.100.1',size=0):
    return dict(id=str(i),time=t,src=src,dst=dst,dst_port=port,bytes_out=size)

class Tests(unittest.TestCase):
    def test_distinct_ports(self):
        self.assertEqual(analyze([row(i,port=80) for i in range(8)]),[])
        self.assertEqual(analyze([row(i,port=80+i) for i in range(5)])[0]['ports'],list(range(80,85)))
    def test_window_boundary(self):
        rows=[row(i,t=i,port=80+i) for i in range(4)]
        self.assertEqual(len(analyze(rows+[row(4,t=60,port=84)])),1)
        self.assertEqual(analyze(rows+[row(4,t=61,port=84)]),[])
    def test_pair_isolation(self):
        self.assertEqual(analyze([row(i,port=80+i,dst=f'198.51.100.{i+1}') for i in range(5)]),[])
    def test_transfer_boundary(self):
        self.assertEqual(analyze([row(1,size=9999999)]),[])
        self.assertEqual(analyze([row(1,size=10000000)])[0]['rule'],'NET-002')
    def test_sort_and_suppression(self):
        rows=[row(i,t=i,port=80+i) for i in range(10)]
        self.assertEqual(analyze(rows),analyze(rows[::-1]))
        self.assertEqual(len(analyze(rows)),1)
    def test_empty_and_config(self):
        self.assertEqual(analyze([]),[])
        with self.assertRaises(ValueError): analyze([],window=0)
    def test_loader_validation(self):
        original=dict(id='1',timestamp='2026-01-01T00:00:00Z',src='192.0.2.1',dst='198.51.100.1',dst_port=80,bytes_out=0)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events.jsonl'
            for field,value in [('src','invalid'),('dst_port',True),('bytes_out',-1),('timestamp','2026-01-01T00:00:00')]:
                changed=original|{field:value}
                path.write_text(json.dumps(changed),encoding='utf-8')
                with self.subTest(field=field),self.assertRaisesRegex(ValueError,'line 1'): load(path)
            path.write_text(json.dumps(original)+'\n'+json.dumps(original),encoding='utf-8')
            with self.assertRaises(ValueError): load(path)
    def test_expected(self):
        expected=json.loads((ROOT/'examples/expected.json').read_text())
        self.assertEqual(analyze(load(ROOT/'data/connections.jsonl')),expected)

if __name__=='__main__': unittest.main()
