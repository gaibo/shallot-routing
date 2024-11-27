import base64
import unittest

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
        data = b'hello world'
        pad_length = 100
        padded_data = crypto.pad_payload(data, pad_length)
        self.assertEqual(len(padded_data), pad_length + 4)
        self.assertEqual(crypto.unpad_payload(padded_data), data)

    def test_generate_cycle(self):
        cycle = crypto.generate_cycle(TEST_USER_LIST, 'Alice', 'Bob', 6)
        self.assertEqual(len(cycle), 6)
        self.assertEqual(cycle[5][0], 'Alice')
        self.assertEqual(cycle[2][0], 'Bob')

    def test_header(self):
        req_id = 1234
        cycle = crypto.generate_cycle(TEST_USER_LIST, 'Alice', 'Bob', 6)
        header = crypto.generate_header(cycle, 'Alice', 'Bob', req_id)
        orig_header_len = len(header)
        for x in range(6):
            f, i, p, header = crypto.decode_header(header, base64.b64decode(TEST_USER_LIST[cycle[x][0]]['prikey']))
            self.assertEqual(len(header), orig_header_len)
            self.assertEqual(f, 3 if x == 5 else 2 if x == 2 else 0)
            self.assertEqual(i, req_id if x == 5 else TEST_USER_LIST[cycle[x + 1][0]]['ip'])
            self.assertEqual(p, 0 if x == 5 else TEST_USER_LIST[cycle[x + 1][0]]['port'])

