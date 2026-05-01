"""
ContactVerifier – фингерпринты SHA-256 и QR-коды (стр. 26).
"""
import hashlib
import base64

class ContactVerifier:
    @staticmethod
    def fingerprint(public_key: bytes) -> str:
        """SHA-256 от публичного идентификационного ключа."""
        return hashlib.sha256(public_key).hexdigest()[:16]  # Укороченный для удобства

    @staticmethod
    def fingerprint_full(public_key: bytes) -> str:
        """Полный SHA-256 фингерпринт."""
        return hashlib.sha256(public_key).hexdigest()

    @staticmethod
    def fingerprint_qr(public_key: bytes) -> str:
        """Возвращает QR-код в виде ASCII для терминала."""
        try:
            import qrcode
            from io import StringIO
            qr = qrcode.QRCode()
            qr.add_data(ContactVerifier.fingerprint_full(public_key))
            qr.make()
            out = StringIO()
            qr.print_ascii(out=out)
            out.seek(0)
            return out.read()
        except ImportError:
            return "QR code requires 'qrcode' module (pip install qrcode[pil])"