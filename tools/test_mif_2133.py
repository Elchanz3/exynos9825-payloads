#!/usr/bin/env python3
"""Offline integration checks against the pinned HWHA BL2 (no private keys)."""
import os
import struct
import unittest
from pathlib import Path

from build_mif_2133 import ECT_OFF, ECT_ROOM, RATES, blocks, dvfs_offsets, patch_ect, table, u32


class MifECTTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ.get('MIF_BASE_BL2',
                    '/home/chanz22/EUB-N10/9825_customkey/ecdsa_green3/sboot/bl2.bin'))
        cls.base = path.read_bytes()[ECT_OFF:ECT_OFF+ECT_ROOM]
        cls.new = patch_ect(cls.base)

    def test_pll_index_isolated_from_boot_level(self):
        level, values = dvfs_offsets(self.new)
        self.assertEqual([u32(self.new, level+8*i) for i in range(10)], [2133000]+RATES[1:])
        old_level, old_values = dvfs_offsets(self.base)
        self.assertEqual(self.new[level+8:values], self.base[old_level+8:old_values])
        self.assertEqual(self.new[values+4:values+200], self.base[old_values+4:old_values+200])
        self.assertEqual(u32(self.new,values),10)
        p = table(self.new,'PLL','PLL_MIF')
        old = table(self.base,'PLL','PLL_MIF')
        self.assertEqual(self.new[p+8:p+208], self.base[old+8:old+208])
        hz,div,mult,shift,k = struct.unpack_from('<5I',self.new,p+208)
        self.assertEqual((hz,div,mult,shift,k),(4264000000,3,492,0,0))
        self.assertEqual(26000000*mult//div//(1<<shift)//2,2132000000)

    def test_all_asv_voltage_tables_and_flags_are_unchanged(self):
        old = table(self.base,'ASV','dvfs_mif')
        new = table(self.new,'ASV','dvfs_mif')
        groups,levels,tables = struct.unpack_from('<3I',self.base,old)
        self.assertEqual((groups,levels,tables),(16,10,5))
        length = 12+levels*4+tables*(12+levels*4+groups*levels)
        self.assertEqual(self.new[new+16:new+length],self.base[old+16:old+length])
        self.assertEqual(u32(self.new,new+12),2133)

    def test_dram_profiles_and_trailing_thermal_data_preserved(self):
        old = blocks(self.base)['NEWTIME'][0]
        new = blocks(self.new)['NEWTIME'][0]
        self.assertEqual(self.base[old:-20],self.new[new:])
        self.assertEqual(len(self.base),len(self.new))

    def test_patch_rejects_reapplication_and_missing_padding(self):
        with self.assertRaises(ValueError):
            patch_ect(self.new)
        invalid = bytearray(self.base)
        invalid[-1] = 1
        with self.assertRaises(ValueError):
            patch_ect(invalid)


if __name__ == '__main__':
    unittest.main()
