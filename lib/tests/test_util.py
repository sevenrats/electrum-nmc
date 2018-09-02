import unittest
from lib.util import format_satoshis, parse_URI

from . import SequentialTestCase


class TestUtil(SequentialTestCase):

    def test_format_satoshis(self):
        result = format_satoshis(1234)
        expected = "0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_negative(self):
        result = format_satoshis(-1234)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def test_format_fee(self):
        result = format_satoshis(1700/1000, 0, 0)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_fee_precision(self):
        result = format_satoshis(1666/1000, 0, 0, precision=6)
        expected = "1.666"
        self.assertEqual(expected, result)

        result = format_satoshis(1666/1000, 0, 0, precision=1)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces(self):
        result = format_satoshis(12340, whitespaces=True)
        expected = "     0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(1234, whitespaces=True)
        expected = "     0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces_negative(self):
        result = format_satoshis(-12340, whitespaces=True)
        expected = "    -0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(-1234, whitespaces=True)
        expected = "    -0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_positive(self):
        result = format_satoshis(1234, is_diff=True)
        expected = "+0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_negative(self):
        result = format_satoshis(-1234, is_diff=True)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def _do_test_parse_URI(self, uri, expected):
        result = parse_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ'})

    def test_parse_URI_only_address(self):
        #self._do_test_parse_URI('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ'})


    def test_parse_URI_address_label(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?label=electrum%20test',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'label': 'electrum test'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ', 'label': 'electrum test'})

    def test_parse_URI_address_message(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?message=electrum%20test',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?message=electrum%20test',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'message': 'electrum test', 'memo': 'electrum test'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ', 'message': 'electrum test', 'memo': 'electrum test'})

    def test_parse_URI_address_amount(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?amount=0.0003',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'amount': 30000})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?r=http://domain.tld/page?h%3D2a8628fc2fbe',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ', 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?test=test',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?test=test',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'test': 'test'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        #self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self._do_test_parse_URI('namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
                                #{'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'amount': 4000, 'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test', 'r': 'http://domain.tld/page', 'test': 'none'})
                                # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
                                {'address': 'N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ', 'amount': 4000, 'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test', 'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('namecoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(BaseException, parse_URI, 'namecoin:invalidaddress')

    def test_parse_URI_invalid(self):
        #self.assertRaises(BaseException, parse_URI, 'notbitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertRaises(BaseException, parse_URI, 'notnamecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ')

    def test_parse_URI_parameter_polution(self):
        #self.assertRaises(Exception, parse_URI, 'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003&label=test&amount=30.0')
        # Converted to Namecoin using `contrib/convertAddress.py` from Namecoin Core.
        self.assertRaises(Exception, parse_URI, 'namecoin:N1LgXEXdjF7G37MPzgwyATN6joULz6LfdQ?amount=0.0003&label=test&amount=30.0')
