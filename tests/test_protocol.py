import socket
import unittest

from chat.protocol import MessageTooLarge, ProtocolError, read_message, send_message
from chat.transport import client_context, server_context


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.sender, self.receiver = socket.socketpair()
        self.receiver.settimeout(1)
        self.addCleanup(self.sender.close)
        self.addCleanup(self.receiver.close)
        self.stream = self.receiver.makefile("rb")
        self.addCleanup(self.stream.close)

    def test_exact_limit_then_another_frame(self):
        self.sender.sendall(b"abcd\nx\n")
        self.assertEqual(read_message(self.stream, 4), "abcd")
        self.assertEqual(read_message(self.stream, 1), "x")

    def test_over_limit_with_or_without_newline(self):
        self.sender.sendall(b"abcde")
        with self.assertRaises(MessageTooLarge):
            read_message(self.stream, 4)

    def test_utf8_limit_is_measured_in_bytes(self):
        self.sender.sendall("שלום\n".encode())
        with self.assertRaises(MessageTooLarge):
            read_message(self.stream, 4)

    def test_partial_frame_at_eof_is_rejected(self):
        self.sender.sendall(b"abc")
        self.sender.shutdown(socket.SHUT_WR)
        with self.assertRaises(ProtocolError):
            read_message(self.stream, 4)

    def test_sender_rejects_line_injection_and_oversize(self):
        with self.assertRaises(ProtocolError):
            send_message(self.sender, "one\ntwo")
        with self.assertRaises(MessageTooLarge):
            send_message(self.sender, "שלום", max_bytes=4)


class TransportTests(unittest.TestCase):
    def test_plaintext_is_allowed_only_for_loopback(self):
        self.assertIsNone(server_context("127.0.0.1"))
        self.assertIsNone(client_context("127.0.0.1"))
        for host in ["0.0.0.0", "10.124.38.204", "example.com"]:
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    server_context(host)
                with self.assertRaises(ValueError):
                    client_context(host)

    def test_partial_tls_configuration_is_rejected(self):
        with self.assertRaises(ValueError):
            server_context("127.0.0.1", certfile="cert.pem")
        with self.assertRaises(ValueError):
            client_context("127.0.0.1", cafile="cert.pem")

    def test_tls_client_verifies_certificates_and_hostnames(self):
        import ssl
        context = client_context("example.com", tls=True)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
