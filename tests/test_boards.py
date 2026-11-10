import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from naos_image_generator import boards
from naos_image_generator.common import BuildError
from test_bootloader import fdt


def resource(entries, hash_size=20):
    block=512
    image=bytearray(block*(1+len(entries)))
    image[:4]=b'RSCE'
    image[8:11]=bytes((1,1,1))
    struct.pack_into('<I',image,12,len(entries))
    for index,(name,payload) in enumerate(entries):
        raw=bytearray(block)
        raw[:4]=b'ENTR'
        encoded=name.encode()
        raw[4:4+len(encoded)]=encoded
        raw[400:408]=b'reserved'
        if hash_size:
            digest=(hashlib.sha1(payload,usedforsecurity=False).digest() if hash_size==20
                    else hashlib.sha256(payload).digest())
            raw[224:224+len(digest)]=digest
        struct.pack_into('<III',raw,256,hash_size,len(image)//block,len(payload))
        image[(index+1)*block:(index+2)*block]=raw
        image.extend(payload)
        image.extend(bytes(-len(image)%block))
    return bytes(image)


class BoardTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.bundle=self.root/'export'
        self.bundle.mkdir()
        self.original=fdt({'model':b'Original\0','compatible':b'mixtile,core3588e\0rockchip,rk3588\0'})
        self.replacement=fdt({'model':b'vision1\0','compatible':b'example,vision1\0rockchip,rk3588\0',
                              'chosen':{'custom':b'new peripheral configuration\0'}})
        (self.bundle/'base-board.dtb').write_bytes(self.original)
        self.logos=[('logo.bmp',b'BM'+bytes(127)),('logo_kernel.bmp',b'BM'+b'K'*513)]
        (self.bundle/'resource.img').write_bytes(resource([('rk-kernel.dtb',self.original),*self.logos]))
        self.board=self.root/'board'
        self.board.mkdir()
        self.selected=self.board/'vision1.dtb'
        self.selected.write_bytes(self.replacement)

    def test_discover_empty_missing_and_sorted_direct_files(self):
        self.assertEqual(boards.discover(self.root/'missing'),())
        empty=self.root/'empty';empty.mkdir()
        self.assertEqual(boards.discover(empty),())
        (self.board/'readme.txt').write_text('no menu entry')
        (self.board/'nested').mkdir()
        (self.board/'nested/ignored.dtb').write_bytes(self.original)
        first=self.board/'alpha.dtb';first.write_bytes(self.original)
        self.assertEqual(boards.discover(self.board),(first.resolve(),self.selected.resolve()))

    def test_discover_rejects_nonordinary_and_unsafe_names(self):
        (self.board/'linked.dtb').symlink_to(self.selected)
        with self.assertRaisesRegex(BuildError,'ordinary file'):
            boards.discover(self.board)
        (self.board/'linked.dtb').unlink()
        (self.board/'invalid name.dtb').write_bytes(self.original)
        with self.assertRaisesRegex(BuildError,'board device-tree name'):
            boards.discover(self.board)

    def test_prepare_preserves_original_names_logos_and_input_bytes(self):
        before={p.name:p.read_bytes() for p in self.bundle.iterdir()}
        selected_before=self.selected.read_bytes()
        dtb,output,info=boards.prepare(self.bundle,'base-board',self.selected,self.root/'work')
        self.assertEqual(dtb.name,'base-board.dtb')
        self.assertEqual(dtb.read_bytes(),self.replacement)
        self.assertEqual(info['name'],'vision1')
        self.assertEqual(info['model'],'vision1')
        self.assertEqual(info['original_name'],'base-board.dtb')
        self.assertEqual(info['resource_dtb_entries'],['rk-kernel.dtb'])
        _,entries=boards._resource_entries(output.read_bytes())
        self.assertEqual([(e['name'],e['payload']) for e in entries],[('rk-kernel.dtb',self.replacement),*self.logos])
        self.assertTrue(all(e['raw'][400:408]==b'reserved' for e in entries))
        self.assertEqual({p.name:p.read_bytes() for p in self.bundle.iterdir()},before)
        self.assertEqual(self.selected.read_bytes(),selected_before)

    def test_replacement_supports_resource_hash_styles_and_dtb_aliases(self):
        for size in (0,20,32):
            with self.subTest(hash_size=size):
                source=self.root/f'resource-{size}.img'
                source.write_bytes(resource([('base-board.dtb',self.original),('alias.dtb',self.original),*self.logos],size))
                output=self.root/f'output-{size}.img'
                replaced=boards.replace_resource(source,output,self.bundle/'base-board.dtb',self.selected,'base-board.dtb')
                self.assertEqual(replaced,['alias.dtb','base-board.dtb'])
                _,entries=boards._resource_entries(output.read_bytes())
                self.assertEqual([e['payload'] for e in entries],[self.replacement,self.replacement,*[e[1] for e in self.logos]])
                self.assertTrue(all(e['hash_size']==size for e in entries))

    def test_larger_dtb_moves_later_resources_without_changing_them(self):
        self.selected.write_bytes(fdt({'model':b'vision1\0','compatible':b'rockchip,rk3588\0',
                                       'large-property':b'P'*2049}))
        before=(self.bundle/'resource.img').read_bytes()
        _,output,_=boards.prepare(self.bundle,'base-board',self.selected,self.root/'work')
        self.assertGreater(output.stat().st_size,len(before))
        _,entries=boards._resource_entries(output.read_bytes())
        self.assertEqual(entries[0]['payload'],self.selected.read_bytes())
        self.assertEqual([(e['name'],e['payload']) for e in entries[1:]],self.logos)
        _,old=boards._resource_entries(before)
        self.assertGreater(struct.unpack_from('<I',entries[1]['raw'],260)[0],
                           struct.unpack_from('<I',old[1]['raw'],260)[0])

    def test_rejects_corrupt_resource_unknown_layout_and_missing_original(self):
        original=(self.bundle/'resource.img').read_bytes()
        cases=[]
        bad=bytearray(original);bad[4]=1;cases.append(bad)
        bad=bytearray(original);bad[struct.unpack_from('<I',bad,512+260)[0]*512+10]^=1;cases.append(bad)
        bad=bytearray(original);struct.pack_into('<I',bad,512+260,0);cases.append(bad)
        bad=bytearray(original);bad[512:516]=b'FAIL';cases.append(bad)
        for number,data in enumerate(cases):
            source=self.root/f'bad-{number}.img';source.write_bytes(data)
            with self.subTest(case=number), self.assertRaises(BuildError):
                boards.replace_resource(source,self.root/'out.img',self.bundle/'base-board.dtb',self.selected,'base-board.dtb')
        source=self.root/'without-dtb.img';source.write_bytes(resource(self.logos))
        with self.assertRaisesRegex(BuildError,'no entry'):
            boards.replace_resource(source,self.root/'out.img',self.bundle/'base-board.dtb',self.selected,'base-board.dtb')

    def test_invalid_dtb_and_incompatible_soc_are_rejected(self):
        self.selected.write_bytes(b'not a device tree')
        with self.assertRaises(BuildError):boards.describe(self.selected)
        self.selected.write_bytes(fdt({'model':b'Other SoC\0','compatible':b'rockchip,rk3568\0'}))
        with self.assertRaisesRegex(BuildError,'RK3588'):
            boards.prepare(self.bundle,'base-board',self.selected,self.root/'work')
        self.assertFalse((self.root/'work').exists())

    def test_work_directory_cannot_modify_export(self):
        before=set(self.bundle.iterdir())
        with self.assertRaisesRegex(BuildError,'outside exported'):
            boards.prepare(self.bundle,'base-board',self.selected,self.bundle/'work')
        self.assertEqual(set(self.bundle.iterdir()),before)


if __name__=='__main__':unittest.main()
