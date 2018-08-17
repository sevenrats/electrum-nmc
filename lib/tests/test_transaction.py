import unittest

from lib import transaction
from lib.bitcoin import TYPE_ADDRESS
from lib.keystore import xpubkey_to_address
from lib.util import bh2u, bfh

from . import SequentialTestCase, TestCaseForTestnet
from .test_bitcoin import needs_test_with_all_ecc_implementations

unsigned_blob = '45505446ff0001000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000005701ff4c53ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
signed_blob = '01000000012a5c9a94fcde98f5581cd00162c60a13936ceb75389ea65bf38633b424eb4031000000006c493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6ffffffff0140420f00000000001976a914230ac37834073a42146f11ef8414ae929feaafc388ac00000000'
v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"
signed_segwit_blob = "01000000000101b66d722484f2db63e827ebf41d02684fed0c6550e85015a6c9d41ef216a8a6f00000000000fdffffff0280c3c90100000000160014b65ce60857f7e7892b983851c2a8e3526d09e4ab64bac30400000000160014c478ebbc0ab2097706a98e10db7cf101839931c4024730440220789c7d47f876638c58d98733c30ae9821c8fa82b470285dcdf6db5994210bf9f02204163418bbc44af701212ad42d884cc613f3d3d831d2d0cc886f767cca6e0235e012103083a6dc250816d771faa60737bfe78b23ad619f6b458e0a1f1688e3a0605e79c00000000"

signed_blob_signatures = ['3046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d98501', ]

class TestBCDataStream(SequentialTestCase):

    def test_compact_size(self):
        s = transaction.BCDataStream()
        values = [0, 1, 252, 253, 2**16-1, 2**16, 2**32-1, 2**32, 2**64-1]
        for v in values:
            s.write_compact_size(v)

        with self.assertRaises(transaction.SerializationError):
            s.write_compact_size(-1)

        self.assertEqual(bh2u(s.input),
                          '0001fcfdfd00fdfffffe00000100feffffffffff0000000001000000ffffffffffffffffff')
        for v in values:
            self.assertEqual(s.read_compact_size(), v)

        with self.assertRaises(transaction.SerializationError):
            s.read_compact_size()

    def test_string(self):
        s = transaction.BCDataStream()
        with self.assertRaises(transaction.SerializationError):
            s.read_string()

        msgs = ['Hello', ' ', 'World', '', '!']
        for msg in msgs:
            s.write_string(msg)
        for msg in msgs:
            self.assertEqual(s.read_string(), msg)

        with self.assertRaises(transaction.SerializationError):
            s.read_string()

    def test_bytes(self):
        s = transaction.BCDataStream()
        s.write(b'foobar')
        self.assertEqual(s.read_bytes(3), b'foo')
        self.assertEqual(s.read_bytes(2), b'ba')
        self.assertEqual(s.read_bytes(4), b'r')
        self.assertEqual(s.read_bytes(1), b'')

class TestTransaction(SequentialTestCase):

    @needs_test_with_all_ecc_implementations
    def test_tx_unsigned(self):
        expected = {
            'inputs': [{
                'type': 'p2pkh',
                #'address': '1446oU3z268EeFgfcwJv6X2VBXHfoYxfuD',
                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                'address': 'MydU17YxwUDoAnwAtkdVK3BPukgii28Tku',
                'num_sig': 1,
                'prevout_hash': '3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a',
                'prevout_n': 0,
                'pubkeys': ['02e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6'],
                'scriptSig': '01ff4c53ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000',
                'sequence': 4294967295,
                'signatures': [None],
                'x_pubkeys': ['ff0488b21e03ef2afea18000000089689bff23e1e7fb2f161daa37270a97a3d8c2e537584b2d304ecb47b86d21fc021b010d3bd425f8cf2e04824bfdf1f1f5ff1d51fadd9a41f9e3fb8dd3403b1bfe00000000']}],
            'lockTime': 0,
            'outputs': [{
                #'address': '14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs',
                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                'address': 'MymekE5Au7Q8MVKJZ19ERsnkRhNanZco6s',
                'prevout_n': 0,
                'scriptPubKey': '76a914230ac37834073a42146f11ef8414ae929feaafc388ac',
                'type': TYPE_ADDRESS,
                'value': 1000000}],
            'partial': True,
            'segwit_ser': False,
            'version': 1,
        }
        tx = transaction.Transaction(unsigned_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)

        self.assertEqual(tx.as_dict(), {'hex': unsigned_blob, 'complete': False, 'final': True})
        #self.assertEqual(tx.get_outputs(), [('14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs', 1000000)])
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual(tx.get_outputs(), [('MymekE5Au7Q8MVKJZ19ERsnkRhNanZco6s', 1000000)])
        #self.assertEqual(tx.get_output_addresses(), ['14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs'])
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual(tx.get_output_addresses(), ['MymekE5Au7Q8MVKJZ19ERsnkRhNanZco6s'])

        #self.assertTrue(tx.has_address('14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertTrue(tx.has_address('MymekE5Au7Q8MVKJZ19ERsnkRhNanZco6s'))
        #self.assertTrue(tx.has_address('1446oU3z268EeFgfcwJv6X2VBXHfoYxfuD'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertTrue(tx.has_address('MydU17YxwUDoAnwAtkdVK3BPukgii28Tku'))
        #self.assertFalse(tx.has_address('1CQj15y1N7LDHp7wTt28eoD1QhHgFgxECH'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertFalse(tx.has_address('N7z6CjTzHVRmpMNSjhLhsKMv8vgj9DZvZV'))

        self.assertEqual(tx.serialize(), unsigned_blob)

        tx.update_signatures(signed_blob_signatures)
        self.assertEqual(tx.raw, signed_blob)

        tx.update(unsigned_blob)
        tx.raw = None
        blob = str(tx)
        self.assertEqual(transaction.deserialize(blob), expected)

    @needs_test_with_all_ecc_implementations
    def test_tx_signed(self):
        expected = {
            'inputs': [{'address': None,
                'num_sig': 0,
                'prevout_hash': '3140eb24b43386f35ba69e3875eb6c93130ac66201d01c58f598defc949a5c2a',
                'prevout_n': 0,
                'scriptSig': '493046022100a82bbc57a0136751e5433f41cf000b3f1a99c6744775e76ec764fb78c54ee100022100f9e80b7de89de861dc6fb0c1429d5da72c2b6b2ee2406bc9bfb1beedd729d985012102e61d176da16edd1d258a200ad9759ef63adf8e14cd97f53227bae35cdb84d2f6',
                'sequence': 4294967295,
                'type': 'unknown'}],
            'lockTime': 0,
            'outputs': [{
                #'address': '14CHYaaByjJZpx4oHBpfDMdqhTyXnZ3kVs',
                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                'address': 'MymekE5Au7Q8MVKJZ19ERsnkRhNanZco6s',
                'prevout_n': 0,
                'scriptPubKey': '76a914230ac37834073a42146f11ef8414ae929feaafc388ac',
                'type': TYPE_ADDRESS,
                'value': 1000000}],
            'partial': False,
            'segwit_ser': False,
            'version': 1
        }
        tx = transaction.Transaction(signed_blob)
        self.assertEqual(tx.deserialize(), expected)
        self.assertEqual(tx.deserialize(), None)
        self.assertEqual(tx.as_dict(), {'hex': signed_blob, 'complete': True, 'final': True})

        self.assertEqual(tx.serialize(), signed_blob)

        tx.update_signatures(signed_blob_signatures)

        self.assertEqual(tx.estimated_total_size(), 193)
        self.assertEqual(tx.estimated_base_size(), 193)
        self.assertEqual(tx.estimated_witness_size(), 0)
        self.assertEqual(tx.estimated_weight(), 772)
        self.assertEqual(tx.estimated_size(), 193)

    def test_estimated_output_size(self):
        estimated_output_size = transaction.Transaction.estimated_output_size
        #self.assertEqual(estimated_output_size('14gcRovpkCoGkCNBivQBvw7eso7eiNAbxG'), 34)
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual(estimated_output_size('MzFydTRofatqGjcgzjim9TGZc2WhgadiiY'), 34)
        #self.assertEqual(estimated_output_size('35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUCQMJbT'), 32)
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual(estimated_output_size('6JGfHAzV5oG2QM2pmoZquwvV9qm1w9yv4A'), 32)
        #self.assertEqual(estimated_output_size('bc1q3g5tmkmlvxryhh843v4dz026avatc0zzr6h3af'), 31)
        # Converted to Namecoin using `contrib/convertBechAddress.py` from Namecoin Core.
        self.assertEqual(estimated_output_size('nc1q3g5tmkmlvxryhh843v4dz026avatc0zzykgka2'), 31)
        #self.assertEqual(estimated_output_size('bc1qnvks7gfdu72de8qv6q6rhkkzu70fqz4wpjzuxjf6aydsx7wxfwcqnlxuv3'), 43)
        # Converted to Namecoin using `contrib/convertBechAddress.py` from Namecoin Core.
        self.assertEqual(estimated_output_size('nc1qnvks7gfdu72de8qv6q6rhkkzu70fqz4wpjzuxjf6aydsx7wxfwcqlygsjk'), 43)

    # TODO other tests for segwit tx
    def test_tx_signed_segwit(self):
        tx = transaction.Transaction(signed_segwit_blob)

        self.assertEqual(tx.estimated_total_size(), 222)
        self.assertEqual(tx.estimated_base_size(), 113)
        self.assertEqual(tx.estimated_witness_size(), 109)
        self.assertEqual(tx.estimated_weight(), 561)
        self.assertEqual(tx.estimated_size(), 141)

    def test_errors(self):
        with self.assertRaises(TypeError):
            transaction.Transaction.pay_script(output_type=None, addr='')

        with self.assertRaises(BaseException):
            xpubkey_to_address('')

    def test_parse_xpub(self):
        res = xpubkey_to_address('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')
        #self.assertEqual(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', '19h943e4diLc68GXW7G75QNe2KWuMu7BaJ'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual(res, ('04ee98d63800824486a1cf5b4376f2f574d86e0a3009a6448105703453f3368e8e1d8d090aaecdd626a45cc49876709a3bbb6dc96a4311b3cac03e225df5f63dfc', 'N5GWFh93Z6SAcfX2mvagHvXYkYuxHwmGpu'))

    def test_version_field(self):
        tx = transaction.Transaction(v2_blob)
        self.assertEqual(tx.txid(), "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe")

    def test_get_address_from_output_script(self):
        # the inverse of this test is in test_bitcoin: test_address_to_script
        addr_from_script = lambda script: transaction.get_address_from_output_script(bfh(script))
        ADDR = transaction.TYPE_ADDRESS

        # bech32 native segwit
        # test vectors from BIP-0173
        #self.assertEqual((ADDR, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), addr_from_script('0014751e76e8199196d454941c45d1b3a323f1433bd6'))
        # Converted to Namecoin using `contrib/convertBechAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, 'nc1qw508d6qejxtdg4y5r3zarvary0c5xw7kttkktk'), addr_from_script('0014751e76e8199196d454941c45d1b3a323f1433bd6'))
        #self.assertEqual((ADDR, 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx'), addr_from_script('5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'))
        # Converted to Namecoin using `contrib/convertBechAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, 'nc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0x5ld6'), addr_from_script('5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'))
        #self.assertEqual((ADDR, 'bc1sw50qa3jx3s'), addr_from_script('6002751e'))
        # Converted to Namecoin using `contrib/convertBechAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, 'nc1sw50q8ctt4n'), addr_from_script('6002751e'))
        #self.assertEqual((ADDR, 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj'), addr_from_script('5210751e76e8199196d454941c45d1b3a323'))
        # Converted to Namecoin using `contrib/convertBechAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, 'nc1zw508d6qejxtdg4y5r3zarvaryvga4wry'), addr_from_script('5210751e76e8199196d454941c45d1b3a323'))

        # base58 p2pkh
        #self.assertEqual((ADDR, '14gcRovpkCoGkCNBivQBvw7eso7eiNAbxG'), addr_from_script('76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, 'MzFydTRofatqGjcgzjim9TGZc2WhgadiiY'), addr_from_script('76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac'))
        #self.assertEqual((ADDR, '1BEqfzh4Y3zzLosfGhw1AsqbEKVW6e1qHv'), addr_from_script('76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, 'N6pCseC3TS6YsM8AYXFaPPzVxYtYykqDNn'), addr_from_script('76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac'))

        # base58 p2sh
        #self.assertEqual((ADDR, '35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUCQMJbT'), addr_from_script('a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, '6JGfHAzV5oG2QM2pmoZquwvV9qm1w9yv4A'), addr_from_script('a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487'))
        #self.assertEqual((ADDR, '3PyjzJ3im7f7bcV724GR57edKDqoZvH7Ji'), addr_from_script('a914f47c8954e421031ad04ecd8e7752c9479206b9d387'))
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertEqual((ADDR, '6cgZsAS2SZN895boDQvxx7pvMFuMDwGfzQ'), addr_from_script('a914f47c8954e421031ad04ecd8e7752c9479206b9d387'))

#####

    def _run_naive_tests_on_tx(self, raw_tx, txid):
        tx = transaction.Transaction(raw_tx)
        self.assertEqual(txid, tx.txid())
        self.assertEqual(raw_tx, tx.serialize())
        self.assertTrue(tx.estimated_size() >= 0)

    def test_txid_coinbase_to_p2pk(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4103400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03ffffffff013c25cf2d01000000434104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac00000000'
        txid = 'dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_coinbase_to_p2pkh(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25033ca0030400001256124d696e656420627920425443204775696c640800000d41000007daffffffff01c00d1298000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000'
        txid = '4328f9311c6defd9ae1bd7f4516b62acf64b361eb39dfcf09d9925c5fd5c61e8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_segwit_coinbase_to_p2pk(self):
        raw_tx = '020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502cd010101ffffffff0240be402500000000232103f4e686cdfc96f375e7c338c40c9b85f4011bb843a3e62e46a1de424ef87e9385ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000'
        txid = 'fb5a57c24e640a6d8d831eb6e41505f3d54363c507da3733b098d820e3803301'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_segwit_coinbase_to_p2pkh(self):
        raw_tx = '020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502c3010101ffffffff0240be4025000000001976a9141ea896d897483e0eb33dd6423f4a07970d0a0a2788ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000'
        txid = 'ed3d100577477d799107eba97e76770b3efa253c7200e9abfb43da5d2b33513e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_segwit_coinbase_to_p2sh(self):
        raw_tx = '020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050214030101ffffffff02902f50090000000017a914ba582096f8647ca4195f55c8ef7e7e6e120e88b1870000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000'
        txid = 'e28ee5866ec0535fe5efac5ad350cbf4960ed981b471a0c4a6baad1d8168d3d7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2pkh(self):
        raw_tx = '010000000118231a31d2df84f884ced6af11dc24306319577d4d7c340124a7e2dd9c314077000000004847304402200b6c45891aed48937241907bc3e3868ee4c792819821fcde33311e5a3da4789a02205021b59692b652a01f5f009bd481acac2f647a7d9c076d71d85869763337882e01fdffffff016c95052a010000001976a9149c4891e7791da9e622532c97f43863768264faaf88ac00000000'
        txid = '90ba90a5b115106d26663fce6c6215b8699c5d4b2672dd30756115f3337dddf9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2sh(self):
        raw_tx = '0100000001e4643183d6497823576d17ac2439fb97eba24be8137f312e10fcc16483bb2d070000000048473044022032bbf0394dfe3b004075e3cbb3ea7071b9184547e27f8f73f967c4b3f6a21fa4022073edd5ae8b7b638f25872a7a308bb53a848baa9b9cc70af45fcf3c683d36a55301fdffffff011821814a0000000017a9143c640bc28a346749c09615b50211cb051faff00f8700000000'
        txid = '172bdf5a690b874385b98d7ab6f6af807356f03a26033c6a65ab79b4ac2085b5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pk_to_p2wpkh(self):
        raw_tx = '01000000015e5e2bf15f5793fdfd01e0ccd380033797ed2d4dba9498426ca84904176c26610000000049483045022100c77aff69f7ab4bb148f9bccffc5a87ee893c4f7f7f96c97ba98d2887a0f632b9022046367bdb683d58fa5b2e43cfc8a9c6d57724a27e03583942d8e7b9afbfeea5ab01fdffffff017289824a00000000160014460fc70f208bffa9abf3ae4abbd2f629d9cdcf5900000000'
        txid = 'ca554b1014952f900aa8cf6e7ab02137a6fdcf933ad6a218de3891a2ef0c350d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2pkh(self):
        raw_tx = '0100000001f9dd7d33f315617530dd72264b5d9c69b815626cce3f66266d1015b1a590ba90000000006a4730440220699bfee3d280a499daf4af5593e8750b54fef0557f3c9f717bfa909493a84f60022057718eec7985b7796bb8630bf6ea2e9bf2892ac21bd6ab8f741a008537139ffe012103b4289890b40590447b57f773b5843bf0400e9cead08be225fac587b3c2a8e973fdffffff01ec24052a010000001976a914ce9ff3d15ed5f3a3d94b583b12796d063879b11588ac00000000'
        txid = '24737c68f53d4b519939119ed83b2a8d44d716d7f3ca98bcecc0fbb92c2085ce'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2sh(self):
        raw_tx = '010000000195232c30f6611b9f2f82ec63f5b443b132219c425e1824584411f3d16a7a54bc000000006b4830450221009f39ac457dc8ff316e5cc03161c9eff6212d8694ccb88d801dbb32e85d8ed100022074230bb05e99b85a6a50d2b71e7bf04d80be3f1d014ea038f93943abd79421d101210317be0f7e5478e087453b9b5111bdad586038720f16ac9658fd16217ffd7e5785fdffffff0200e40b540200000017a914d81df3751b9e7dca920678cc19cac8d7ec9010b08718dfd63c2c0000001976a914303c42b63569ff5b390a2016ff44651cd84c7c8988acc7010000'
        txid = '155e4740fa59f374abb4e133b87247dccc3afc233cb97c2bf2b46bba3094aedc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2pkh_to_p2wpkh(self):
        raw_tx = '0100000001ce85202cb9fbc0ecbc98caf3d716d7448d2a3bd89e113999514b3df5687c7324000000006b483045022100adab7b6cb1179079c9dfc0021f4db0346730b7c16555fcc4363059dcdd95f653022028bcb816f4fb98615fb8f4b18af3ad3708e2d72f94a6466cc2736055860422cf012102a16a25148dd692462a691796db0a4a5531bcca970a04107bf184a2c9f7fd8b12fdffffff012eb6042a010000001600147d0170de18eecbe84648979d52b666dddee0b47400000000'
        txid = 'ed29e100499e2a3a64a2b0cb3a68655b9acd690d29690fa541be530462bf3d3c'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2sh_to_p2pkh(self):
        raw_tx = '01000000000101f9823f87af35d158e7dc81a67011f4e511e3f6cab07ac108e524b0ff8b950b39000000002322002041f0237866eb72e4a75cd6faf5ccd738703193907d883aa7b3a8169c636706a9fdffffff020065cd1d000000001976a9148150cd6cf729e7e262699875fec1f760b0aab3cc88acc46f9a3b0000000017a91433ccd0f95a7b9d8eef68be40bb59c64d6e14d87287040047304402205ca97126a5956c2deaa956a2006d79a348775d727074a04b71d9c18eb5e5525402207b9353497af15881100a2786adab56c8930c02d46cc1a8b55496c06e22d3459b01483045022100b4fa898057927c2d920ae79bca752dda58202ea8617d3e6ed96cbd5d1c0eb2fc02200824c0e742d1b4d643cec439444f5d8779c18d4f42c2c87cce24044a3babf2df0147522102db78786b3c214826bd27010e3c663b02d67144499611ee3f2461c633eb8f1247210377082028c124098b59a5a1e0ea7fd3ebca72d59c793aecfeedd004304bac15cd52aec9010000'
        txid = '17e1d498ba82503e3bfa81ac4897a57e33f3d36b41bcf4765ba604466c478986'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2sh_to_p2sh(self):
        raw_tx = '01000000000101b58520acb479ab656a3c03263af0567380aff6b67a8db98543870b695adf2b170000000017160014cfd2b9f7ed9d4d4429ed6946dbb3315f75e85f14fdffffff020065cd1d0000000017a91485f5681bec38f9f07ae9790d7f27c2bb90b5b63c87106ab32c0000000017a914ff402e164dfce874435641ae9ac41fc6fb14c4e18702483045022100b3d1c89c7c92151ed1df78815924569446782776b6a2c170ca5d74c5dd1ad9b102201d7bab1974fd2aa66546dd15c1f1e276d787453cec31b55a2bd97b050abf20140121024a1742ece86df3dbce4717c228cf51e625030cef7f5e6dde33a4fffdd17569eac7010000'
        txid = 'ead0e7abfb24ddbcd6b89d704d7a6091e43804a458baa930adf6f1cb5b6b42f7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2sh_to_p2wpkh(self):
        raw_tx = '010000000001018689476c4604a65b76f4bc416bd3f3337ea59748ac81fa3b3e5082ba98d4e1170100000023220020ae40340707f9726c0f453c3d47c96e7f3b7b4b85608eb3668b69bbef9c7ab374fdffffff0218b2cc1d0000000017a914f2fdd81e606ff2ab804d7bb46bf8838a711c277b870065cd1d0000000016001496ad8959c1f0382984ecc4da61c118b4c8751e5104004730440220387b9e7d402fbcada9ba55a27a8d0563eafa9904ebd2f8f7e3d86e4b45bc0ec202205f37fa0e2bf8cbd384f804562651d7c6f69adce5db4c1a5b9103250a47f73e6b01473044022074903f4dd4fd6b32289be909eb5109924740daa55e79be6dbd728687683f9afa02205d934d981ca12cbec450611ca81dc4127f8da5e07dd63d41049380502de3f15401475221025c3810b37147105106cef970f9b91d3735819dee4882d515c1187dbd0b8f0c792103e007c492323084f1c103beff255836408af89bb9ae7f2fcf60502c28ff4b0c9152aeca010000'
        txid = '6f294c84cbd0241650931b4c1be3dfb2f175d682c7a9538b30b173e1083deed3'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2wpkh_to_p2pkh(self):
        raw_tx = '0100000000010197e6bf4a70bc118e3a8d9842ed80422e335679dfc29b5ba0f9123f6a5863b8470000000000fdffffff02402bca7f130000001600146f579c953d9e7e7719f2baa20bde22eb5f24119200e87648170000001976a9140cd8fa5fd81c3acf33f93efd179b388de8dd693388ac0247304402204ff33b3ea8fb270f62409bfc257457ca5eb1fec5e4d3a7c11aa487207e131d4d022032726b998e338e5245746716e5cd0b40d32b69d1535c3d841f049d98a5d819b1012102dc3ce3220363aff579eb2c45c973e8b186a829c987c3caea77c61975666e7d1bc8010000'
        txid = 'c721ed35767a3a209b688e68e3bb136a72d2b631fe81c56be8bdbb948c343dbc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2wpkh_to_p2sh(self):
        raw_tx = '010000000001013c3dbf620453be41a50f69290d69cd9a5b65683acbb0a2643a2a9e4900e129ed0000000000fdffffff02002f68590000000017a914c7c4dcd0ddf70f15c6df13b4a4d56e9f13c49b2787a0429cd000000000160014e514e3ecf89731e7853e4f3a20983484c569d3910247304402205368cc548209303db5a8f2ebc282bd0f7af0d080ce0f7637758587f94d3971fb0220098cec5752554758bc5fa4de332b980d5e0054a807541581dc5e4de3ed29647501210233717cd73d95acfdf6bd72c4fb5df27cd6bd69ce947daa3f4a442183a97877efc8010000'
        txid = '390b958bffb024e508c17ab0caf6e311e5f41170a681dce758d135af873f82f9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_p2wpkh_to_p2wpkh(self):
        raw_tx = '010000000001010d350cefa29138de18a2d63a93cffda63721b07a6ecfa80a902f9514104b55ca0000000000fdffffff012a4a824a00000000160014b869999d342a5d42d6dc7af1efc28456da40297a024730440220475bb55814a52ea1036919e4408218c693b8bf93637b9f54c821b5baa3b846e102207276ed7a79493142c11fb01808a4142bbdd525ae7bdccdf8ecb7b8e3c856b4d90121024cdeaca7a53a7e23a1edbe9260794eaa83063534b5f111ee3c67d8b0cb88f0eec8010000'
        txid = '51087ece75c697cc872d2e643d646b0f3e1f2666fa1820b7bff4343d50dd680e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_input_p2wsh_p2sh_not_multisig(self):
        raw_tx = '0100000000010160f84fdcda039c3ca1b20038adea2d49a53db92f7c467e8def13734232bb610804000000232200202814720f16329ab81cb8867c4d447bd13255931f23e6655944c9ada1797fcf88ffffffff0ba3dcfc04000000001976a91488124a57c548c9e7b1dd687455af803bd5765dea88acc9f44900000000001976a914da55045a0ccd40a56ce861946d13eb861eb5f2d788ac49825e000000000017a914ca34d4b190e36479aa6e0023cfe0a8537c6aa8dd87680c0d00000000001976a914651102524c424b2e7c44787c4f21e4c54dffafc088acf02fa9000000000017a914ee6c596e6f7066466d778d4f9ba633a564a6e95d874d250900000000001976a9146ca7976b48c04fd23867748382ee8401b1d27c2988acf5119600000000001976a914cf47d5dcdba02fd547c600697097252d38c3214a88ace08a12000000000017a914017bef79d92d5ec08c051786bad317e5dd3befcf87e3d76201000000001976a9148ec1b88b66d142bcbdb42797a0fd402c23e0eec288ac718f6900000000001976a914e66344472a224ce6f843f2989accf435ae6a808988ac65e51300000000001976a914cad6717c13a2079066f876933834210ebbe68c3f88ac0347304402201a4907c4706104320313e182ecbb1b265b2d023a79586671386de86bb47461590220472c3db9fc99a728ebb9b555a72e3481d20b181bd059a9c1acadfb853d90c96c01210338a46f2a54112fef8803c8478bc17e5f8fc6a5ec276903a946c1fafb2e3a8b181976a914eda8660085bf607b82bd18560ca8f3a9ec49178588ac00000000'
        txid = 'e9933221a150f78f9f224899f8568ff6422ffcc28ca3d53d87936368ff7c4b1d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    # input: p2sh, not multisig
    def test_txid_regression_issue_3899(self):
        raw_tx = '0100000004328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c010000000b0009630330472d5fae685bffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c020000000b0009630359646d5fae6858ffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c030000000b000963034bd4715fae6854ffffffff328685b0352c981d3d451b471ae3bfc78b82565dc2a54049a81af273f0a9fd9c040000000b000963036de8705fae6860ffffffff0130750000000000001976a914b5abca61d20f9062fb1fdbb880d9d93bac36675188ac00000000'
        txid = 'f570d5d1e965ee61bcc7005f8fefb1d3abbed9d7ddbe035e2a68fa07e5fc4a0d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_negative_version_num(self):
        raw_tx = 'f0b47b9a01ecf5e5c3bbf2cf1f71ecdc7f708b0b222432e914b394e24aad1494a42990ddfc000000008b483045022100852744642305a99ad74354e9495bf43a1f96ded470c256cd32e129290f1fa191022030c11d294af6a61b3da6ed2c0c296251d21d113cfd71ec11126517034b0dcb70014104a0fe6e4a600f859a0932f701d3af8e0ecd4be886d91045f06a5a6b931b95873aea1df61da281ba29cadb560dad4fc047cf47b4f7f2570da4c0b810b3dfa7e500ffffffff0240420f00000000001976a9147eeacb8a9265cd68c92806611f704fc55a21e1f588ac05f00d00000000001976a914eb3bd8ccd3ba6f1570f844b59ba3e0a667024a6a88acff7f0000'
        txid = 'c659729a7fea5071361c2c1a68551ca2bf77679b27086cc415adeeb03852e369'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_regression_issue_4333(self):
        raw_tx = '0100000001a300499298b3f03200c05d1a15aa111a33c769aff6fb355c6bf52ebdb58ca37100000000171600756161616161616161616161616161616161616151fdffffff01c40900000000000017a914001975d5f07f3391674416c1fcd67fd511d257ff871bc71300'
        txid = '9b9f39e314662a7433aadaa5c94a2f1e24c7e7bf55fc9e1f83abd72be933eb95'
        self._run_naive_tests_on_tx(raw_tx, txid)


# these transactions are from Bitcoin Core unit tests --->
# https://github.com/bitcoin/bitcoin/blob/11376b5583a283772c82f6d32d0007cdbf5b8ef0/src/test/data/tx_valid.json

    def test_txid_bitcoin_core_0001(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000490047304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = '23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0002(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a0048304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2bab01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'fcabc409d8e685da28536e1e5ccc91264d755cd4c57ed4cae3dbaa4d3b93e8ed'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0003(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba260000000004a01ff47304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'c9aa95f2c48175fdb70b34c23f1c3fc44f869b073a6f79b1343fbce30c3cb575'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0004(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000495147304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'da94fda32b55deb40c3ed92e135d69df7efc4ee6665e0beb07ef500f407c9fd2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0005(self):
        raw_tx = '0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa43ad90ba26000000000494f47304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae360ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4db743ce7ca2b01ffffffff0140420f00000000001976a914660d4ef3a743e3e696ad990364e555c271ad504b88ac00000000'
        txid = 'f76f897b206e4f78d60fe40f2ccb542184cfadc34354d3bb9bdc30cc2f432b86'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0006(self):
        raw_tx = '01000000010276b76b07f4935c70acf54fbf1f438a4c397a9fb7e633873c4dd3bc062b6b40000000008c493046022100d23459d03ed7e9511a47d13292d3430a04627de6235b6e51a40f9cd386f2abe3022100e7d25b080f0bb8d8d5f878bba7d54ad2fda650ea8d158a33ee3cbd11768191fd004104b0e2c879e4daf7b9ab68350228c159766676a14f5815084ba166432aab46198d4cca98fa3e9981d0a90b2effc514b76279476550ba3663fdcaff94c38420e9d5000000000100093d00000000001976a9149a7b0f3b80c6baaeedce0a0842553800f832ba1f88ac00000000'
        txid = 'c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0007(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000'
        txid = 'e41ffe19dff3cbedb413a2ca3fbbcd05cb7fd7397ffa65052f8928aa9c700092'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0008(self):
        raw_tx = '01000000023d6cf972d4dff9c519eff407ea800361dd0a121de1da8b6f4138a2f25de864b4000000008a4730440220ffda47bfc776bcd269da4832626ac332adfca6dd835e8ecd83cd1ebe7d709b0e022049cffa1cdc102a0b56e0e04913606c70af702a1149dc3b305ab9439288fee090014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff21ebc9ba20594737864352e95b727f1a565756f9d365083eb1a8596ec98c97b7010000008a4730440220503ff10e9f1e0de731407a4a245531c9ff17676eda461f8ceeb8c06049fa2c810220c008ac34694510298fa60b3f000df01caa244f165b727d4896eb84f81e46bcc4014104266abb36d66eb4218a6dd31f09bb92cf3cfa803c7ea72c1fc80a50f919273e613f895b855fb7465ccbc8919ad1bd4a306c783f22cd3227327694c4fa4c1c439affffffff01f0da5200000000001976a914857ccd42dded6df32949d4646dfa10a92458cfaa88ac00000000'
        txid = 'f7fdd091fa6d8f5e7a8c2458f5c38faffff2d3f1406b6e4fe2c99dcc0d2d1cbb'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0009(self):
        raw_tx = '01000000020002000000000000000000000000000000000000000000000000000000000000000000000151ffffffff0001000000000000000000000000000000000000000000000000000000000000000000006b483045022100c9cdd08798a28af9d1baf44a6c77bcc7e279f47dc487c8c899911bc48feaffcc0220503c5c50ae3998a733263c5c0f7061b483e2b56c4c41b456e7d2f5a78a74c077032102d5c25adb51b61339d2b05315791e21bbe80ea470a49db0135720983c905aace0ffffffff010000000000000000015100000000'
        txid = 'b56471690c3ff4f7946174e51df68b47455a0d29344c351377d712e6d00eabe5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0010(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000009085768617420697320ffffffff010000000000000000015100000000'
        txid = '99517e5b47533453cc7daa332180f578be68b80370ecfe84dbfff7f19d791da4'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0011(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006e493046022100c66c9cdf4c43609586d15424c54707156e316d88b0a1534c9e6b0d4f311406310221009c0fe51dbc9c4ab7cc25d3fdbeccf6679fe6827f08edf2b4a9f16ee3eb0e438a0123210338e8034509af564c62644c07691942e0c056752008a173c89f60ab2a88ac2ebfacffffffff010000000000000000015100000000'
        txid = 'ab097537b528871b9b64cb79a769ae13c3c3cd477cc9dddeebe657eabd7fdcea'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0012(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006e493046022100e1eadba00d9296c743cb6ecc703fd9ddc9b3cd12906176a226ae4c18d6b00796022100a71aef7d2874deff681ba6080f1b278bac7bb99c61b08a85f4311970ffe7f63f012321030c0588dc44d92bdcbf8e72093466766fdc265ead8db64517b0c542275b70fffbacffffffff010040075af0750700015100000000'
        txid = '4d163e00f1966e9a1eab8f9374c3e37f4deb4857c247270e25f7d79a999d2dc9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0013(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000006d483045022027deccc14aa6668e78a8c9da3484fbcd4f9dcc9bb7d1b85146314b21b9ae4d86022100d0b43dece8cfb07348de0ca8bc5b86276fa88f7f2138381128b7c36ab2e42264012321029bb13463ddd5d2cc05da6e84e37536cb9525703cfd8f43afdb414988987a92f6acffffffff020040075af075070001510000000000000000015100000000'
        txid = '9fe2ef9dde70e15d78894a4800b7df3bbfb1addb9a6f7d7c204492fdb6ee6cc4'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0014(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff025151ffffffff010000000000000000015100000000'
        txid = '99d3825137602e577aeaf6a2e3c9620fd0e605323dc5265da4a570593be791d4'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0015(self):
        raw_tx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff6451515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151515151ffffffff010000000000000000015100000000'
        txid = 'c0d67409923040cc766bbea12e4c9154393abef706db065ac2e07d91a9ba4f84'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0016(self):
        raw_tx = '010000000200010000000000000000000000000000000000000000000000000000000000000000000049483045022100d180fd2eb9140aeb4210c9204d3f358766eb53842b2a9473db687fa24b12a3cc022079781799cd4f038b85135bbe49ec2b57f306b2bb17101b17f71f000fcab2b6fb01ffffffff0002000000000000000000000000000000000000000000000000000000000000000000004847304402205f7530653eea9b38699e476320ab135b74771e1c48b81a5d041e2ca84b9be7a802200ac8d1f40fb026674fe5a5edd3dea715c27baa9baca51ed45ea750ac9dc0a55e81ffffffff010100000000000000015100000000'
        txid = 'c610d85d3d5fdf5046be7f123db8a0890cee846ee58de8a44667cfd1ab6b8666'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0017(self):
        raw_tx = '01000000020001000000000000000000000000000000000000000000000000000000000000000000004948304502203a0f5f0e1f2bdbcd04db3061d18f3af70e07f4f467cbc1b8116f267025f5360b022100c792b6e215afc5afc721a351ec413e714305cb749aae3d7fee76621313418df101010000000002000000000000000000000000000000000000000000000000000000000000000000004847304402205f7530653eea9b38699e476320ab135b74771e1c48b81a5d041e2ca84b9be7a802200ac8d1f40fb026674fe5a5edd3dea715c27baa9baca51ed45ea750ac9dc0a55e81ffffffff010100000000000000015100000000'
        txid = 'a647a7b3328d2c698bfa1ee2dd4e5e05a6cea972e764ccb9bd29ea43817ca64f'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0018(self):
        raw_tx = '010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c59da0a5cf63000000006a4730440220360d20baff382059040ba9be98947fd678fb08aab2bb0c172efa996fd8ece9b702201b4fb0de67f015c90e7ac8a193aeab486a1f587e0f54d0fb9552ef7f5ce6caec032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff7d815b6447e35fbea097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e804010000006b483045022100c714310be1e3a9ff1c5f7cacc65c2d8e781fc3a88ceb063c6153bf950650802102200b2d0979c76e12bb480da635f192cc8dc6f905380dd4ac1ff35a4f68f462fffd032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff3f1f097333e4d46d51f5e77b53264db8f7f5d2e18217e1099957d0f5af7713ee010000006c493046022100b663499ef73273a3788dea342717c2640ac43c5a1cf862c9e09b206fcb3f6bb8022100b09972e75972d9148f2bdd462e5cb69b57c1214b88fc55ca638676c07cfc10d8032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff0380841e00000000001976a914bfb282c70c4191f45b5a6665cad1682f2c9cfdfb88ac80841e00000000001976a9149857cc07bed33a5cf12b9c5e0500b675d500c81188ace0fd1c00000000001976a91443c52850606c872403c0601e69fa34b26f62db4a88ac00000000'
        txid = 'afd9c17f8913577ec3509520bd6e5d63e9c0fd2a5f70c787993b097ba6ca9fae'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0019(self):
        raw_tx = '01000000012312503f2491a2a97fcd775f11e108a540a5528b5d4dee7a3c68ae4add01dab300000000fdfe0000483045022100f6649b0eddfdfd4ad55426663385090d51ee86c3481bdc6b0c18ea6c0ece2c0b0220561c315b07cffa6f7dd9df96dbae9200c2dee09bf93cc35ca05e6cdf613340aa0148304502207aacee820e08b0b174e248abd8d7a34ed63b5da3abedb99934df9fddd65c05c4022100dfe87896ab5ee3df476c2655f9fbe5bd089dccbef3e4ea05b5d121169fe7f5f4014c695221031d11db38972b712a9fe1fc023577c7ae3ddb4a3004187d41c45121eecfdbb5b7210207ec36911b6ad2382860d32989c7b8728e9489d7bbc94a6b5509ef0029be128821024ea9fac06f666a4adc3fc1357b7bec1fd0bdece2b9d08579226a8ebde53058e453aeffffffff0180380100000000001976a914c9b99cddf847d10685a4fabaa0baf505f7c3dfab88ac00000000'
        txid = 'f4b05f978689c89000f729cae187dcfbe64c9819af67a4f05c0b4d59e717d64d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0020(self):
        raw_tx = '0100000001f709fa82596e4f908ee331cb5e0ed46ab331d7dcfaf697fe95891e73dac4ebcb000000008c20ca42095840735e89283fec298e62ac2ddea9b5f34a8cbb7097ad965b87568100201b1b01dc829177da4a14551d2fc96a9db00c6501edfa12f22cd9cefd335c227f483045022100a9df60536df5733dd0de6bc921fab0b3eee6426501b43a228afa2c90072eb5ca02201c78b74266fac7d1db5deff080d8a403743203f109fbcabf6d5a760bf87386d20100ffffffff01c075790000000000232103611f9a45c18f28f06f19076ad571c344c82ce8fcfe34464cf8085217a2d294a6ac00000000'
        txid = 'cc60b1f899ec0a69b7c3f25ddf32c4524096a9c5b01cbd84c6d0312a0c478984'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0021(self):
        raw_tx = '01000000012c651178faca83be0b81c8c1375c4b0ad38d53c8fe1b1c4255f5e795c25792220000000049483045022100d6044562284ac76c985018fc4a90127847708c9edb280996c507b28babdc4b2a02203d74eca3f1a4d1eea7ff77b528fde6d5dc324ec2dbfdb964ba885f643b9704cd01ffffffff010100000000000000232102c2410f8891ae918cab4ffc4bb4a3b0881be67c7a1e7faa8b5acf9ab8932ec30cac00000000'
        txid = '1edc7f214659d52c731e2016d258701911bd62a0422f72f6c87a1bc8dd3f8667'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0022(self):
        raw_tx = '0100000001f725ea148d92096a79b1709611e06e94c63c4ef61cbae2d9b906388efd3ca99c000000000100ffffffff0101000000000000002321028a1d66975dbdf97897e3a4aef450ebeb5b5293e4a0b4a6d3a2daaa0b2b110e02ac00000000'
        txid = '018adb7133fde63add9149a2161802a1bcf4bdf12c39334e880c073480eda2ff'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0023(self):
        raw_tx = '0100000001be599efaa4148474053c2fa031c7262398913f1dc1d9ec201fd44078ed004e44000000004900473044022022b29706cb2ed9ef0cb3c97b72677ca2dfd7b4160f7b4beb3ba806aa856c401502202d1e52582412eba2ed474f1f437a427640306fd3838725fab173ade7fe4eae4a01ffffffff010100000000000000232103ac4bba7e7ca3e873eea49e08132ad30c7f03640b6539e9b59903cf14fd016bbbac00000000'
        txid = '1464caf48c708a6cc19a296944ded9bb7f719c9858986d2501cf35068b9ce5a2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0024(self):
        raw_tx = '010000000112b66d5e8c7d224059e946749508efea9d66bf8d0c83630f080cf30be8bb6ae100000000490047304402206ffe3f14caf38ad5c1544428e99da76ffa5455675ec8d9780fac215ca17953520220779502985e194d84baa36b9bd40a0dbd981163fa191eb884ae83fc5bd1c86b1101ffffffff010100000000000000232103905380c7013e36e6e19d305311c1b81fce6581f5ee1c86ef0627c68c9362fc9fac00000000'
        txid = '1fb73fbfc947d52f5d80ba23b67c06a232ad83fdd49d1c0a657602f03fbe8f7a'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0025(self):
        raw_tx = '0100000001b0ef70cc644e0d37407e387e73bfad598d852a5aa6d691d72b2913cebff4bceb000000004a00473044022068cd4851fc7f9a892ab910df7a24e616f293bcb5c5fbdfbc304a194b26b60fba022078e6da13d8cb881a22939b952c24f88b97afd06b4c47a47d7f804c9a352a6d6d0100ffffffff0101000000000000002321033bcaa0a602f0d44cc9d5637c6e515b0471db514c020883830b7cefd73af04194ac00000000'
        txid = '24cecfce0fa880b09c9b4a66c5134499d1b09c01cc5728cd182638bea070e6ab'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0026(self):
        raw_tx = '0100000001c188aa82f268fcf08ba18950f263654a3ea6931dabc8bf3ed1d4d42aaed74cba000000004b0000483045022100940378576e069aca261a6b26fb38344e4497ca6751bb10905c76bb689f4222b002204833806b014c26fd801727b792b1260003c55710f87c5adbd7a9cb57446dbc9801ffffffff0101000000000000002321037c615d761e71d38903609bf4f46847266edc2fb37532047d747ba47eaae5ffe1ac00000000'
        txid = '9eaa819e386d6a54256c9283da50c230f3d8cd5376d75c4dcc945afdeb157dd7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0027(self):
        raw_tx = '01000000012432b60dc72cebc1a27ce0969c0989c895bdd9e62e8234839117f8fc32d17fbc000000004a493046022100a576b52051962c25e642c0fd3d77ee6c92487048e5d90818bcf5b51abaccd7900221008204f8fb121be4ec3b24483b1f92d89b1b0548513a134e345c5442e86e8617a501ffffffff010000000000000000016a00000000'
        txid = '46224764c7870f95b58f155bce1e38d4da8e99d42dbb632d0dd7c07e092ee5aa'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0028(self):
        raw_tx = '01000000014710b0e7cf9f8930de259bdc4b84aa5dfb9437b665a3e3a21ff26e0bf994e183000000004a493046022100a166121a61b4eeb19d8f922b978ff6ab58ead8a5a5552bf9be73dc9c156873ea02210092ad9bc43ee647da4f6652c320800debcf08ec20a094a0aaf085f63ecb37a17201ffffffff010000000000000000016a00000000'
        txid = '8d66836045db9f2d7b3a75212c5e6325f70603ee27c8333a3bce5bf670d9582e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0029(self):
        raw_tx = '01000000015ebaa001d8e4ec7a88703a3bcf69d98c874bca6299cca0f191512bf2a7826832000000004948304502203bf754d1c6732fbf87c5dcd81258aefd30f2060d7bd8ac4a5696f7927091dad1022100f5bcb726c4cf5ed0ed34cc13dadeedf628ae1045b7cb34421bc60b89f4cecae701ffffffff010000000000000000016a00000000'
        txid = 'aab7ef280abbb9cc6fbaf524d2645c3daf4fcca2b3f53370e618d9cedf65f1f8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0030(self):
        raw_tx = '010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a900000000924830450221009c0a27f886a1d8cb87f6f595fbc3163d28f7a81ec3c4b252ee7f3ac77fd13ffa02203caa8dfa09713c8c4d7ef575c75ed97812072405d932bd11e6a1593a98b679370148304502201e3861ef39a526406bad1e20ecad06be7375ad40ddb582c9be42d26c3a0d7b240221009d0a3985e96522e59635d19cc4448547477396ce0ef17a58e7d74c3ef464292301ffffffff010000000000000000016a00000000'
        txid = '6327783a064d4e350c454ad5cd90201aedf65b1fc524e73709c52f0163739190'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0031(self):
        raw_tx = '010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a48304502207a6974a77c591fa13dff60cabbb85a0de9e025c09c65a4b2285e47ce8e22f761022100f0efaac9ff8ac36b10721e0aae1fb975c90500b50c56e8a0cc52b0403f0425dd0100ffffffff010000000000000000016a00000000'
        txid = '892464645599cc3c2d165adcc612e5f982a200dfaa3e11e9ce1d228027f46880'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0032(self):
        raw_tx = '010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510151ffffffff010000000000000000016a00000000'
        txid = '578db8c6c404fec22c4a8afeaf32df0e7b767c4dda3478e0471575846419e8fc'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0033(self):
        raw_tx = '0100000001e0be9e32f1f89c3d916c4f21e55cdcd096741b895cc76ac353e6023a05f4f7cc00000000d86149304602210086e5f736a2c3622ebb62bd9d93d8e5d76508b98be922b97160edc3dcca6d8c47022100b23c312ac232a4473f19d2aeb95ab7bdf2b65518911a0d72d50e38b5dd31dc820121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac4730440220508fa761865c8abd81244a168392876ee1d94e8ed83897066b5e2df2400dad24022043f5ee7538e87e9c6aef7ef55133d3e51da7cc522830a9c4d736977a76ef755c0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = '974f5148a0946f9985e75a240bb24c573adbbdc25d61e7b016cdbb0a5355049f'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0034(self):
        raw_tx = '01000000013c6f30f99a5161e75a2ce4bca488300ca0c6112bde67f0807fe983feeff0c91001000000e608646561646265656675ab61493046022100ce18d384221a731c993939015e3d1bcebafb16e8c0b5b5d14097ec8177ae6f28022100bcab227af90bab33c3fe0a9abfee03ba976ee25dc6ce542526e9b2e56e14b7f10121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac493046022100c3b93edcc0fd6250eb32f2dd8a0bba1754b0f6c3be8ed4100ed582f3db73eba2022100bf75b5bd2eff4d6bf2bda2e34a40fcc07d4aa3cf862ceaa77b47b81eff829f9a01ab21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = 'b0097ec81df231893a212657bf5fe5a13b2bff8b28c0042aca6fc4159f79661b'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0035(self):
        raw_tx = '01000000016f3dbe2ca96fa217e94b1017860be49f20820dea5c91bdcb103b0049d5eb566000000000fd1d0147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac47304402203757e937ba807e4a5da8534c17f9d121176056406a6465054bdd260457515c1a02200f02eccf1bec0f3a0d65df37889143c2e88ab7acec61a7b6f5aa264139141a2b0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = 'feeba255656c80c14db595736c1c7955c8c0a497622ec96e3f2238fbdd43a7c9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0036(self):
        raw_tx = '01000000012139c555ccb81ee5b1e87477840991ef7b386bc3ab946b6b682a04a621006b5a01000000fdb40148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f2204148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390175ac4830450220646b72c35beeec51f4d5bc1cbae01863825750d7f490864af354e6ea4f625e9c022100f04b98432df3a9641719dbced53393022e7249fb59db993af1118539830aab870148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a580039017521038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000'
        txid = 'a0c984fc820e57ddba97f8098fa640c8a7eb3fe2f583923da886b7660f505e1e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0037(self):
        raw_tx = '0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987ba3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c60598ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e68700000000'
        txid = '5df1375ffe61ac35ca178ebb0cab9ea26dedbd0e96005dfcee7e379fa513232f'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0038(self):
        raw_tx = '0100000002dbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce000000006b4830450221009627444320dc5ef8d7f68f35010b4c050a6ed0d96b67a84db99fda9c9de58b1e02203e4b4aaa019e012e65d69b487fdf8719df72f488fa91506a80c49a33929f1fd50121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffffdbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce010000009300483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303ffffffff01a0860100000000001976a9149bc0bbdd3024da4d0c38ed1aecf5c68dd1d3fa1288ac00000000'
        txid = 'ded7ff51d89a4e1ec48162aee5a96447214d93dfb3837946af2301a28f65dbea'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0039(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000'
        txid = '3444be2e216abe77b46015e481d8cc21abd4c20446aabf49cd78141c9b9db87e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0040(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000ff64cd1d'
        txid = 'abd62b4627d8d9b2d95fcfd8c87e37d2790637ce47d28018e3aece63c1d62649'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0041(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000065cd1d'
        txid = '58b6de8413603b7f556270bf48caedcf17772e7105f5419f6a80be0df0b470da'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0042(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000ffffffff'
        txid = '5f99c0abf511294d76cbe144d86b77238a03e086974bc7a8ea0bdb2c681a0324'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0043(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000feffffff0100000000000000000000000000'
        txid = '25d35877eaba19497710666473c50d5527d38503e3521107a3fc532b74cd7453'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0044(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000feffffff'
        txid = '1b9aef851895b93c62c29fbd6ca4d45803f4007eff266e2f96ff11e9b6ef197b'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0045(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000'
        txid = '3444be2e216abe77b46015e481d8cc21abd4c20446aabf49cd78141c9b9db87e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0046(self):
        raw_tx = '01000000010001000000000000000000000000000000000000000000000000000000000000000000000251b1000000000100000000000000000001000000'
        txid = 'f53761038a728b1f17272539380d96e93f999218f8dcb04a8469b523445cd0fd'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0047(self):
        raw_tx = '0100000001000100000000000000000000000000000000000000000000000000000000000000000000030251b1000000000100000000000000000001000000'
        txid = 'd193f0f32fceaf07bb25c897c8f99ca6f69a52f6274ca64efc2a2e180cb97fc1'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0048(self):
        raw_tx = '010000000132211bdd0d568506804eef0d8cc3db68c3d766ab9306cdfcc0a9c89616c8dbb1000000006c493045022100c7bb0faea0522e74ff220c20c022d2cb6033f8d167fb89e75a50e237a35fd6d202203064713491b1f8ad5f79e623d0219ad32510bfaa1009ab30cbee77b59317d6e30001210237af13eb2d84e4545af287b919c2282019c9691cc509e78e196a9d8274ed1be0ffffffff0100000000000000001976a914f1b3ed2eda9a2ebe5a9374f692877cdf87c0f95b88ac00000000'
        txid = '50a1e0e6a134a564efa078e3bd088e7e8777c2c0aec10a752fd8706470103b89'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0049(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000'
        txid = 'e2207d1aaf6b74e5d98c2fa326d2dc803b56b30a3f90ce779fa5edb762f38755'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0050(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffff00000100000000000000000000000000'
        txid = 'f335864f7c12ec7946d2c123deb91eb978574b647af125a414262380c7fbd55c'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0051(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffbf7f0100000000000000000000000000'
        txid = 'd1edbcde44691e98a7b7f556bd04966091302e29ad9af3c2baac38233667e0d2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0052(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000000040000100000000000000000000000000'
        txid = '3a13e1b6371c545147173cc4055f0ed73686a9f73f092352fb4b39ca27d360e6'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0053(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffff40000100000000000000000000000000'
        txid = 'bffda23e40766d292b0510a1b556453c558980c70c94ab158d8286b3413e220d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0054(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffff7f0100000000000000000000000000'
        txid = '01a86c65460325dc6699714d26df512a62a854a669f6ed2e6f369a238e048cfd'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0055(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000000000800100000000000000000000000000'
        txid = 'f6d2359c5de2d904e10517d23e7c8210cca71076071bbf46de9fbd5f6233dbf1'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0056(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000feffffff0100000000000000000000000000'
        txid = '19c2b7377229dae7aa3e50142a32fd37cef7171a01682f536e9ffa80c186f6c9'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0057(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100000000000000000000000000'
        txid = 'c9dda3a24cc8a5acb153d1085ecd2fecf6f87083122f8cdecc515b1148d4c40d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0058(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffbf7f0100000000000000000000000000'
        txid = 'd1edbcde44691e98a7b7f556bd04966091302e29ad9af3c2baac38233667e0d2'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0059(self):
        raw_tx = '020000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffff7f0100000000000000000000000000'
        txid = '01a86c65460325dc6699714d26df512a62a854a669f6ed2e6f369a238e048cfd'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0060(self):
        raw_tx = '02000000010001000000000000000000000000000000000000000000000000000000000000000000000251b2010000000100000000000000000000000000'
        txid = '4b5e0aae1251a9dc66b4d5f483f1879bf518ea5e1765abc5a9f2084b43ed1ea7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0061(self):
        raw_tx = '0200000001000100000000000000000000000000000000000000000000000000000000000000000000030251b2010000000100000000000000000000000000'
        txid = '5f16eb3ca4581e2dfb46a28140a4ee15f85e4e1c032947da8b93549b53c105f5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0062(self):
        raw_tx = '0100000000010100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac02483045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc44502200a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7100000000'
        txid = 'b2ce556154e5ab22bec0a2f990b2b843f4f4085486c0d2cd82873685c0012004'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0063(self):
        raw_tx = '0100000000010100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac02483045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb022022dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01232103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ac00000000'
        txid = 'b2ce556154e5ab22bec0a2f990b2b843f4f4085486c0d2cd82873685c0012004'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0064(self):
        raw_tx = '01000000000101000100000000000000000000000000000000000000000000000000000000000000000000171600144c9c3dfac4207d5d8cb89df5722cb3d712385e3fffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac02483045022100cfb07164b36ba64c1b1e8c7720a56ad64d96f6ef332d3d37f9cb3c96477dc44502200a464cd7a9cf94cd70f66ce4f4f0625ef650052c7afcfe29d7d7e01830ff91ed012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7100000000'
        txid = 'fee125c6cd142083fabd0187b1dd1f94c66c89ec6e6ef6da1374881c0c19aece'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0065(self):
        raw_tx = '0100000000010100010000000000000000000000000000000000000000000000000000000000000000000023220020ff25429251b5a84f452230a3c75fd886b7fc5a7865ce4a7bb7a9d7c5be6da3dbffffffff01e8030000000000001976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac02483045022100aa5d8aa40a90f23ce2c3d11bc845ca4a12acd99cbea37de6b9f6d86edebba8cb022022dedc2aa0a255f74d04c0b76ece2d7c691f9dd11a64a8ac49f62a99c3a05f9d01232103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ac00000000'
        txid = '5f32557914351fee5f89ddee6c8983d476491d29e601d854e3927299e50450da'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0066(self):
        raw_tx = '0100000000010400010000000000000000000000000000000000000000000000000000000000000200000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000300000000ffffffff05540b0000000000000151d0070000000000000151840300000000000001513c0f00000000000001512c010000000000000151000248304502210092f4777a0f17bf5aeb8ae768dec5f2c14feabf9d1fe2c89c78dfed0f13fdb86902206da90a86042e252bcd1e80a168c719e4a1ddcc3cebea24b9812c5453c79107e9832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71000000000000'
        txid = '07dfa2da3d67c8a2b9f7bd31862161f7b497829d5da90a88ba0f1a905e7a43f7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0067(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b0000000000000151000248304502210092f4777a0f17bf5aeb8ae768dec5f2c14feabf9d1fe2c89c78dfed0f13fdb86902206da90a86042e252bcd1e80a168c719e4a1ddcc3cebea24b9812c5453c79107e9832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '8a1bddf924d24570074b09d7967c145e54dc4cee7972a92fd975a2ad9e64b424'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0068(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff0484030000000000000151d0070000000000000151540b0000000000000151c800000000000000015100024730440220699e6b0cfe015b64ca3283e6551440a34f901ba62dd4c72fe1cb815afb2e6761022021cc5e84db498b1479de14efda49093219441adc6c543e5534979605e273d80b032103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = 'f92bb6e4f3ff89172f23ef647f74c13951b665848009abb5862cdf7a0412415a'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0069(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b000000000000015100024730440220699e6b0cfe015b64ca3283e6551440a34f901ba62dd4c72fe1cb815afb2e6761022021cc5e84db498b1479de14efda49093219441adc6c543e5534979605e273d80b032103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '8a1bddf924d24570074b09d7967c145e54dc4cee7972a92fd975a2ad9e64b424'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0070(self):
        raw_tx = '0100000000010400010000000000000000000000000000000000000000000000000000000000000200000000ffffffff00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000300000000ffffffff04b60300000000000001519e070000000000000151860b00000000000001009600000000000000015100000248304502210091b32274295c2a3fa02f5bce92fb2789e3fc6ea947fbe1a76e52ea3f4ef2381a022079ad72aefa3837a2e0c033a8652a59731da05fa4a813f4fc48e87c075037256b822103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = 'e657e25fc9f2b33842681613402759222a58cf7dd504d6cdc0b69a0b8c2e7dcb'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0071(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b0000000000000151000248304502210091b32274295c2a3fa02f5bce92fb2789e3fc6ea947fbe1a76e52ea3f4ef2381a022079ad72aefa3837a2e0c033a8652a59731da05fa4a813f4fc48e87c075037256b822103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '8a1bddf924d24570074b09d7967c145e54dc4cee7972a92fd975a2ad9e64b424'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0072(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff04b60300000000000001519e070000000000000151860b0000000000000100960000000000000001510002473044022022fceb54f62f8feea77faac7083c3b56c4676a78f93745adc8a35800bc36adfa022026927df9abcf0a8777829bcfcce3ff0a385fa54c3f9df577405e3ef24ee56479022103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '4ede5e22992d43d42ccdf6553fb46e448aa1065ba36423f979605c1e5ab496b8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0073(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b00000000000001510002473044022022fceb54f62f8feea77faac7083c3b56c4676a78f93745adc8a35800bc36adfa022026927df9abcf0a8777829bcfcce3ff0a385fa54c3f9df577405e3ef24ee56479022103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '8a1bddf924d24570074b09d7967c145e54dc4cee7972a92fd975a2ad9e64b424'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0074(self):
        raw_tx = '01000000000103000100000000000000000000000000000000000000000000000000000000000000000000000200000000010000000000000000000000000000000000000000000000000000000000000100000000ffffffff000100000000000000000000000000000000000000000000000000000000000002000000000200000003e8030000000000000151d0070000000000000151b80b00000000000001510002473044022022fceb54f62f8feea77faac7083c3b56c4676a78f93745adc8a35800bc36adfa022026927df9abcf0a8777829bcfcce3ff0a385fa54c3f9df577405e3ef24ee56479022103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = 'cfe9f4b19f52b8366860aec0d2b5815e329299b2e9890d477edd7f1182be7ac8'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0075(self):
        raw_tx = '0100000000010400010000000000000000000000000000000000000000000000000000000000000200000000ffffffff00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000300000000ffffffff03e8030000000000000151d0070000000000000151b80b0000000000000151000002483045022100a3cec69b52cba2d2de623eeef89e0ba1606184ea55476c0f8189fda231bc9cbb022003181ad597f7c380a7d1c740286b1d022b8b04ded028b833282e055e03b8efef812103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = 'aee8f4865ca40fa77ff2040c0d7de683bea048b103d42ca406dc07dd29d539cb'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0076(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b00000000000001510002483045022100a3cec69b52cba2d2de623eeef89e0ba1606184ea55476c0f8189fda231bc9cbb022003181ad597f7c380a7d1c740286b1d022b8b04ded028b833282e055e03b8efef812103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '8a1bddf924d24570074b09d7967c145e54dc4cee7972a92fd975a2ad9e64b424'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0077(self):
        raw_tx = '0100000000010300010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000200000000ffffffff03e8030000000000000151d0070000000000000151b80b00000000000001510002483045022100a3cec69b52cba2d2de623ffffffffff1606184ea55476c0f8189fda231bc9cbb022003181ad597f7c380a7d1c740286b1d022b8b04ded028b833282e055e03b8efef812103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = '8a1bddf924d24570074b09d7967c145e54dc4cee7972a92fd975a2ad9e64b424'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0078(self):
        raw_tx = '0100000000010100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff010000000000000000015102fd08020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002755100000000'
        txid = 'd93ab9e12d7c29d2adc13d5cdf619d53eec1f36eb6612f55af52be7ba0448e97'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0079(self):
        raw_tx = '0100000000010c00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff0001000000000000000000000000000000000000000000000000000000000000020000006a473044022026c2e65b33fcd03b2a3b0f25030f0244bd23cc45ae4dec0f48ae62255b1998a00220463aa3982b718d593a6b9e0044513fd67a5009c2fdccc59992cffc2b167889f4012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ffffffff0001000000000000000000000000000000000000000000000000000000000000030000006a4730440220008bd8382911218dcb4c9f2e75bf5c5c3635f2f2df49b36994fde85b0be21a1a02205a539ef10fb4c778b522c1be852352ea06c67ab74200977c722b0bc68972575a012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ffffffff0001000000000000000000000000000000000000000000000000000000000000040000006b483045022100d9436c32ff065127d71e1a20e319e4fe0a103ba0272743dbd8580be4659ab5d302203fd62571ee1fe790b182d078ecfd092a509eac112bea558d122974ef9cc012c7012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ffffffff0001000000000000000000000000000000000000000000000000000000000000050000006a47304402200e2c149b114ec546015c13b2b464bbcb0cdc5872e6775787527af6cbc4830b6c02207e9396c6979fb15a9a2b96ca08a633866eaf20dc0ff3c03e512c1d5a1654f148012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ffffffff0001000000000000000000000000000000000000000000000000000000000000060000006b483045022100b20e70d897dc15420bccb5e0d3e208d27bdd676af109abbd3f88dbdb7721e6d6022005836e663173fbdfe069f54cde3c2decd3d0ea84378092a5d9d85ec8642e8a41012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ffffffff00010000000000000000000000000000000000000000000000000000000000000700000000ffffffff00010000000000000000000000000000000000000000000000000000000000000800000000ffffffff00010000000000000000000000000000000000000000000000000000000000000900000000ffffffff00010000000000000000000000000000000000000000000000000000000000000a00000000ffffffff00010000000000000000000000000000000000000000000000000000000000000b0000006a47304402206639c6e05e3b9d2675a7f3876286bdf7584fe2bbd15e0ce52dd4e02c0092cdc60220757d60b0a61fc95ada79d23746744c72bac1545a75ff6c2c7cdb6ae04e7e9592012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71ffffffff0ce8030000000000000151e9030000000000000151ea030000000000000151eb030000000000000151ec030000000000000151ed030000000000000151ee030000000000000151ef030000000000000151f0030000000000000151f1030000000000000151f2030000000000000151f30300000000000001510248304502210082219a54f61bf126bfc3fa068c6e33831222d1d7138c6faa9d33ca87fd4202d6022063f9902519624254d7c2c8ea7ba2d66ae975e4e229ae38043973ec707d5d4a83012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7102473044022017fb58502475848c1b09f162cb1688d0920ff7f142bed0ef904da2ccc88b168f02201798afa61850c65e77889cbcd648a5703b487895517c88f85cdd18b021ee246a012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7100000000000247304402202830b7926e488da75782c81a54cd281720890d1af064629ebf2e31bf9f5435f30220089afaa8b455bbeb7d9b9c3fe1ed37d07685ade8455c76472cda424d93e4074a012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7102473044022026326fcdae9207b596c2b05921dbac11d81040c4d40378513670f19d9f4af893022034ecd7a282c0163b89aaa62c22ec202cef4736c58cd251649bad0d8139bcbf55012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc71024730440220214978daeb2f38cd426ee6e2f44131a33d6b191af1c216247f1dd7d74c16d84a02205fdc05529b0bc0c430b4d5987264d9d075351c4f4484c16e91662e90a72aab24012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710247304402204a6e9f199dc9672cf2ff8094aaa784363be1eb62b679f7ff2df361124f1dca3302205eeb11f70fab5355c9c8ad1a0700ea355d315e334822fa182227e9815308ee8f012103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710000000000'
        txid = 'b83579db5246aa34255642768167132a0c3d2932b186cd8fb9f5490460a0bf91'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0080(self):
        raw_tx = '010000000100010000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803000000000000015100000000'
        txid = '2b1e44fff489d09091e5e20f9a01bbc0e8d80f0662e629fd10709cdb4922a874'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0081(self):
        raw_tx = '0100000000010200010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff01d00700000000000001510003483045022100e078de4e96a0e05dcdc0a414124dd8475782b5f3f0ed3f607919e9a5eeeb22bf02201de309b3a3109adb3de8074b3610d4cf454c49b61247a2779a0bcbf31c889333032103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc711976a9144c9c3dfac4207d5d8cb89df5722cb3d712385e3f88ac00000000'
        txid = '60ebb1dd0b598e20dd0dd462ef6723dd49f8f803b6a2492926012360119cfdd7'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0082(self):
        raw_tx = '0100000000010200010000000000000000000000000000000000000000000000000000000000000000000000ffffffff00010000000000000000000000000000000000000000000000000000000000000100000000ffffffff02e8030000000000000151e90300000000000001510247304402206d59682663faab5e4cb733c562e22cdae59294895929ec38d7c016621ff90da0022063ef0af5f970afe8a45ea836e3509b8847ed39463253106ac17d19c437d3d56b832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710248304502210085001a820bfcbc9f9de0298af714493f8a37b3b354bfd21a7097c3e009f2018c022050a8b4dbc8155d4d04da2f5cdd575dcf8dd0108de8bec759bd897ea01ecb3af7832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7100000000'
        txid = 'ed0c7f4163e275f3f77064f471eac861d01fdf55d03aa6858ebd3781f70bf003'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0083(self):
        raw_tx = '0100000000010200010000000000000000000000000000000000000000000000000000000000000100000000ffffffff00010000000000000000000000000000000000000000000000000000000000000000000000ffffffff02e9030000000000000151e80300000000000001510248304502210085001a820bfcbc9f9de0298af714493f8a37b3b354bfd21a7097c3e009f2018c022050a8b4dbc8155d4d04da2f5cdd575dcf8dd0108de8bec759bd897ea01ecb3af7832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc710247304402206d59682663faab5e4cb733c562e22cdae59294895929ec38d7c016621ff90da0022063ef0af5f970afe8a45ea836e3509b8847ed39463253106ac17d19c437d3d56b832103596d3451025c19dbbdeb932d6bf8bfb4ad499b95b6f88db8899efac102e5fc7100000000'
        txid = 'f531ddf5ce141e1c8a7fdfc85cc634e5ff686f446a5cf7483e9dbe076b844862'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0084(self):
        raw_tx = '01000000020001000000000000000000000000000000000000000000000000000000000000000000004847304402202a0b4b1294d70540235ae033d78e64b4897ec859c7b6f1b2b1d8a02e1d46006702201445e756d2254b0f1dfda9ab8e1e1bc26df9668077403204f32d16a49a36eb6983ffffffff00010000000000000000000000000000000000000000000000000000000000000100000049483045022100acb96cfdbda6dc94b489fd06f2d720983b5f350e31ba906cdbd800773e80b21c02200d74ea5bdf114212b4bbe9ed82c36d2e369e302dff57cb60d01c428f0bd3daab83ffffffff02e8030000000000000151e903000000000000015100000000'
        txid = '98229b70948f1c17851a541f1fe532bf02c408267fecf6d7e174c359ae870654'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0085(self):
        raw_tx = '01000000000102fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e000000004847304402200af4e47c9b9629dbecc21f73af989bdaa911f7e6f6c2e9394588a3aa68f81e9902204f3fcf6ade7e5abb1295b6774c8e0abd94ae62217367096bc02ee5e435b67da201ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac000347304402200de66acf4527789bfda55fc5459e214fa6083f936b430a762c629656216805ac0220396f550692cd347171cbc1ef1f51e15282e837bb2b30860dc77c8f78bc8501e503473044022027dc95ad6b740fe5129e7e62a75dd00f291a2aeb1200b84b09d9e3789406b6c002201a9ecd315dd6a0e632ab20bbb98948bc0c6fb204f2c286963bb48517a7058e27034721026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac00000000'
        txid = '570e3730deeea7bd8bc92c836ccdeb4dd4556f2c33f2a1f7b889a4cb4e48d3ab'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0086(self):
        raw_tx = '01000000000102e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000'
        txid = 'e0b8142f587aaa322ca32abce469e90eda187f3851043cc4f2a0fff8c13fc84e'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0087(self):
        raw_tx = '0100000000010280e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffffe9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff0280969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac80969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac024730440220032521802a76ad7bf74d0e2c218b72cf0cbc867066e2e53db905ba37f130397e02207709e2188ed7f08f4c952d9d13986da504502b8c3be59617e043552f506c46ff83275163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac02483045022100f6a10b8604e6dc910194b79ccfc93e1bc0ec7c03453caaa8987f7d6c3413566002206216229ede9b4d6ec2d325be245c5b508ff0339bf1794078e20bfe0babc7ffe683270063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac00000000'
        txid = 'b9ecf72df06b8f98f8b63748d1aded5ffc1a1186f8a302e63cf94f6250e29f4d'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0088(self):
        raw_tx = '0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000'
        txid = '27eae69aff1dd4388c0fa05cbbfe9a3983d1b0b5811ebcd4199b86f299370aac'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0089(self):
        raw_tx = '010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f1581b0000b64830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0121037a3fb04bcdb09eba90f69961ba1692a3528e45e67c85b200df820212d7594d334aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01ffffffff0101000000000000000000000000'
        txid = '22d020638e3b7e1f2f9a63124ac76f5e333c74387862e3675f64b25e960d3641'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0090(self):
        raw_tx = '0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61fb5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000'
        txid = '2862bc0c69d2af55da7284d1b16a7cddc03971b77e5a97939cca7631add83bf5'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0091(self):
        raw_tx = '01000000019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a662896581b0000fd6f01004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c03959601522102cd74a2809ffeeed0092bc124fd79836706e41f048db3f6ae9df8708cefb83a1c2102e615999372426e46fd107b76eaf007156a507584aa2cc21de9eee3bdbd26d36c4c9552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960175ffffffff0101000000000000000000000000'
        txid = '1aebf0c98f01381765a8c33d688f8903e4d01120589ac92b78f1185dc1f4119c'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_bitcoin_core_0092(self):
        raw_tx = '010000000001019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a6628964c1d000000ffffffff0101000000000000000007004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960101022102966f109c54e85d3aee8321301136cedeb9fc710fdef58a9de8a73942f8e567c021034ffc99dd9a79dd3cb31e2ab3e0b09e0e67db41ac068c625cd1f491576016c84e9552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c039596017500000000'
        txid = '45d17fb7db86162b2b6ca29fa4e163acf0ef0b54110e49b819bda1f948d423a3'
        self._run_naive_tests_on_tx(raw_tx, txid)

# txns from Bitcoin Core ends <---


class TestTransactionTestnet(TestCaseForTestnet):

    def _run_naive_tests_on_tx(self, raw_tx, txid):
        tx = transaction.Transaction(raw_tx)
        self.assertEqual(txid, tx.txid())
        self.assertEqual(raw_tx, tx.serialize())
        self.assertTrue(tx.estimated_size() >= 0)

# partial txns using our partial format --->
    # NOTE: our partial format contains xpubs, and xpubs have version bytes,
    # and version bytes encode the network as well; so these are network-sensitive!

    def test_txid_partial_segwit_p2wpkh(self):
        raw_tx = '45505446ff000100000000010115a847356cbb44be67f345965bb3f2589e2fec1c9a0ada21fd28225dcc602e8f0100000000fdffffff02f6fd1200000000001600149c756aa33f4f89418b33872a973274b5445c727b80969800000000001600140f9de573bc679d040e763d13f0250bd03e625f6ffeffffffff9095ab000000000000000201ff53ff045f1cf6014af5fa07800000002fa3f450ba41799b9b62642979505817783a9b6c656dc11cd0bb4fa362096808026adc616c25a4d0a877d1741eb1db9cef65c15118bd7d5f31bf65f319edda81840100c8000f391400'
        txid = '63ff7e99d85d8e33f683e6ec84574bdf8f5111078a5fe900893e019f9a7f95c3'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_partial_segwit_p2wpkh_p2sh_simple(self):
        raw_tx = '45505446ff0001000000000101d0d23a6fbddb21cc664cb81cca96715baa4d6dbe5b7b9bcc6632f1005a7b0b840100000017160014a78a91261e71a681b6312cd184b14503a21f856afdffffff0134410f000000000017a914d6514ca17ecc31952c990daf96e307fbc58529cd87feffffffff40420f000000000000000201ff53ff044a5262033601222e800000001618aa51e49a961f63fd111f64cd4a7e792c1d7168be7a07703de505ebed2cf70286ebbe755767adaa5835f4d78dec1ee30849d69eacfe80b7ee6b1585279536c30000020011391400'
        txid = '2739f2e7fde9b8ec73fce4aee53722cc7683312d1321ded073284c51fadf44df'
        self._run_naive_tests_on_tx(raw_tx, txid)

    def test_txid_partial_segwit_p2wpkh_p2sh_mixed_outputs(self):
        raw_tx = '45505446ff00010000000001011dcac788f24b84d771b60c44e1f9b6b83429e50f06e1472d47241922164013b00100000017160014801d28ca6e2bde551112031b6cb75de34f10851ffdffffff0440420f00000000001600140f9de573bc679d040e763d13f0250bd03e625f6fc0c62d000000000017a9142899f6484e477233ce60072fc185ef4c1f2c654487809698000000000017a914d40f85ba3c8fa0f3615bcfa5d6603e36dfc613ef87712d19040000000017a914e38c0cffde769cb65e72cda1c234052ae8d2254187feffffffff6ad1ee040000000000000201ff53ff044a5262033601222e800000001618aa51e49a961f63fd111f64cd4a7e792c1d7168be7a07703de505ebed2cf70286ebbe755767adaa5835f4d78dec1ee30849d69eacfe80b7ee6b1585279536c301000c000f391400'
        txid = 'ba5c88e07a4025a39ad3b85247cbd4f556a70d6312b18e04513c7cec9d45d6ac'
        self._run_naive_tests_on_tx(raw_tx, txid)

# end partial txns <---


class NetworkMock(object):

    def __init__(self, unspent):
        self.unspent = unspent

    def synchronous_send(self, arg):
        return self.unspent
