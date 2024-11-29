import base64
import unittest
from config import CRYPTO
import crypto


TEST_USER_LIST = {
    'Alice': {
        'ip': '1.1.1.1',
        'port': 1111,
        'prikey': b'KDYONFS8ikaX3fgpdh7pZtLT9h8el6VYRu2sdCfnxmc=',
        'pubkey': b'QaVCI0irnVBjc9GXuFqraOxjiTd+blzYy53tDrDArXM=',
    }, 'Bob': {
        'ip': '1.1.1.2',
        'port': 2222,
        'prikey': b'8METnd5B/jbnZAFJo+9WMqM9Nf2WwWEzqEeRctUoKUY=',
        'pubkey': b'wUi/9XM/6pPnJaPq/hiY6Sy++CU63Gi/8wRgfuMkvjc=',
    }, 'Carol': {
        'ip': '1.1.1.3',
        'port': 3333,
        'prikey': b'yMgoGe1Bxx1Sw33kOZVnhdwZbUOQgcsvtS+3DzVXDHI=',
        'pubkey': b'NxYUalnwKZNSX+UdLIW7Nfahw0ADbKkzCkHykhHOMVQ=',
    }, 'Dan': {
        'ip': '1.1.1.4',
        'port': 4444,
        'prikey': b'WFopaaOmKBK8np0Pp3tH/oLOr5YrzSnWy5KwSglEM38=',
        'pubkey': b'0JH6legyr2IgWitW++lQmorWYNx88MU+yJgK9COj0lQ=',
    }, 'Erin': {
        'ip': '1.1.1.5',
        'port': 5555,
        'prikey': b'ECKXqsTm8QTk4ZpLHHH1QnJdffMjVhz/fz8Vg178bW4=',
        'pubkey': b'EegTGqoDV14BI9JeJFjIOu/9Fh+qfY/piIgmGYbYhgg=',
    }, 'Frank': {
        'ip': '1.1.1.6',
        'port': 6666,
        'prikey': b'iMTVmVcP+V++4jhElTsqpyWuNSZPT3Z9US1jxhl+K0g=',
        'pubkey': b'QNRpZlJWuG1nMAOsk/lMkWjTTadK8hC1OeFkZQC2lkw=',
    }
}

class TestCrypto(unittest.TestCase):
    def test_pad_payload(self):
        """Test padding and unpadding of payloads."""
        data = b'hello world'
        pad_length = 100
        padded_data = crypto.pad_payload(data, pad_length)
        self.assertEqual(len(padded_data), pad_length)
        self.assertEqual(crypto.unpad_payload(padded_data), data)

        with self.assertRaises(ValueError):
            crypto.pad_payload(data, len(data) - 1)  # Test invalid size

    def test_unpad_malformed_payload(self):
        """Test unpadding a malformed payload."""
        malformed_data = b'\x00\x00\x00\x10hello world'  # Length doesn't match actual data
        with self.assertRaises(ValueError):
            crypto.unpad_payload(malformed_data)

    def test_generate_cycle(self):
        """Test the generation of routing cycles."""
        cycle = crypto.generate_cycle(TEST_USER_LIST, 'Alice', 'Bob', 6)
        self.assertEqual(len(cycle), 6)
        self.assertEqual(cycle[5][0], 'Alice')  # Origin node at the end
        self.assertEqual(cycle[2][0], 'Bob')   # Destination node in the middle
        self.assertNotEqual(cycle[1][0], 'Alice')  # Intermediate nodes
        self.assertNotEqual(cycle[3][0], 'Alice')

        with self.assertRaises(ValueError):
            crypto.generate_cycle(TEST_USER_LIST, 'Alice', 'Bob', 5)  # Cycle length too short

        with self.assertRaises(ValueError):
            crypto.generate_cycle({'Alice': TEST_USER_LIST['Alice']}, 'Alice', 'Bob', 6)  # Not enough users

    def test_header(self):
        """Test Shallot header generation and decoding."""
        req_id = 1234
        cycle_length = 6
        cycle = crypto.generate_cycle(TEST_USER_LIST, 'Alice', 'Bob', cycle_length)
        header = crypto.generate_header(cycle, 'Alice', 'Bob', req_id)
        orig_header_len = len(header)

        self.assertEqual(crypto.get_header_size(cycle_length), orig_header_len)

        for x in range(6):
            f, i, p, header = crypto.decode_header(header, base64.b64decode(TEST_USER_LIST[cycle[x][0]]['prikey']))
            self.assertEqual(len(header), orig_header_len)
            self.assertEqual(f, 3 if x == 5 else 2 if x == 2 else 0)
            self.assertEqual(i, req_id if x == 5 else TEST_USER_LIST[cycle[x + 1][0]]['ip'])
            self.assertEqual(p, 0 if x == 5 else TEST_USER_LIST[cycle[x + 1][0]]['port'])

    def test_encrypt_decrypt(self):
        """Test encryption and decryption of data."""
        sender_prikey = base64.b64decode(TEST_USER_LIST['Alice']['prikey'])
        recipient_pubkey = base64.b64decode(TEST_USER_LIST['Alice']['pubkey'])
        data = b'This is a test message.'

        encrypted_data = crypto.encrypt(recipient_pubkey, data)
        decrypted_data = crypto.decrypt(sender_prikey, encrypted_data)
        self.assertEqual(decrypted_data, data)

    def test_encrypt_with_invalid_key(self):
        """Test encryption with an invalid public key."""
        invalid_pubkey = b'\x00' * CRYPTO.X25519_SIZE  # Invalid key
        data = b'This is a test message.'
        with self.assertRaises(Exception):
            crypto.encrypt(invalid_pubkey, data)

    def test_decrypt_with_invalid_data(self):
        """Test decryption with malformed or invalid data."""
        sender_prikey = base64.b64decode(TEST_USER_LIST['Alice']['prikey'])
        malformed_data = b'\x00' * 50  # Invalid encrypted data
        with self.assertRaises(Exception):
            crypto.decrypt(sender_prikey, malformed_data)

    def test_get_header_size(self):
        """Test calculation of header size."""
        cycle_length = 6
        expected_size = (crypto._HEADER_STRUCT.size + crypto._ENCRYPT_HEADER_STRUCT.size) * cycle_length
        self.assertEqual(crypto.get_header_size(cycle_length), expected_size)

        cycle_length = 10
        expected_size = (crypto._HEADER_STRUCT.size + crypto._ENCRYPT_HEADER_STRUCT.size) * cycle_length
        self.assertEqual(crypto.get_header_size(cycle_length), expected_size)
