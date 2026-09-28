"""
Tests for encryption and envelope key management
"""
import os
import pytest
from cryptography.fernet import InvalidToken, Fernet
from src.utils.encryption import FileEncryption


def test_roundtrip(tmp_path):
    """Verify encryption and decryption roundtrip preserves file content."""
    key = FileEncryption.generate_key()
    src = tmp_path / "a.txt"
    enc = tmp_path / "b.enc"
    dec = tmp_path / "c.txt"

    original_bytes = os.urandom(1024 * 64)  # 64 KB
    src.write_bytes(original_bytes)

    assert FileEncryption.encrypt_file(str(src), str(enc), key)
    assert enc.exists()
    assert enc.read_bytes() != original_bytes  # Ciphertext differs from plaintext

    assert FileEncryption.decrypt_file(str(enc), str(dec), key)
    assert dec.exists()
    assert dec.read_bytes() == original_bytes


def test_empty_file_roundtrip(tmp_path):
    """Verify 0-byte boundary encryption and decryption."""
    key = FileEncryption.generate_key()
    src = tmp_path / "empty.txt"
    enc = tmp_path / "empty.enc"
    dec = tmp_path / "empty_dec.txt"

    src.write_bytes(b"")
    assert FileEncryption.encrypt_file(str(src), str(enc), key)
    assert enc.exists()
    assert FileEncryption.decrypt_file(str(enc), str(dec), key)
    assert dec.read_bytes() == b""


def test_wrong_key_raises_invalid_token():
    """Verify decrypting with a mismatched key raises InvalidToken."""
    key1 = FileEncryption.generate_key()
    key2 = FileEncryption.generate_key()
    data = b"confidential document content"

    encrypted = FileEncryption.encrypt_data(data, key1)

    with pytest.raises(InvalidToken):
        FileEncryption.decrypt_data(encrypted, key2)


def test_corrupted_ciphertext_raises_invalid_token():
    """Verify single flipped byte in ciphertext raises InvalidToken (HMAC verification)."""
    key = FileEncryption.generate_key()
    data = b"financial data"
    encrypted = bytearray(FileEncryption.encrypt_data(data, key))

    # Flip a byte in the payload
    encrypted[-1] ^= 0xFF

    with pytest.raises(InvalidToken):
        FileEncryption.decrypt_data(bytes(encrypted), key)


def test_envelope_key_wrap_unwrap():
    """Verify envelope encryption wrapping and unwrapping of per-file data keys."""
    master_key = Fernet.generate_key()
    data_key = FileEncryption.generate_key()

    wrapped_key = FileEncryption.wrap_key(data_key, master_key)
    assert wrapped_key != data_key

    unwrapped_key = FileEncryption.unwrap_key(wrapped_key, master_key)
    assert unwrapped_key == data_key


def test_envelope_unwrap_with_wrong_master_key():
    """Verify unwrapping with an incorrect master key raises InvalidToken."""
    master_key1 = Fernet.generate_key()
    master_key2 = Fernet.generate_key()
    data_key = FileEncryption.generate_key()

    wrapped_key = FileEncryption.wrap_key(data_key, master_key1)

    with pytest.raises(InvalidToken):
        FileEncryption.unwrap_key(wrapped_key, master_key2)
