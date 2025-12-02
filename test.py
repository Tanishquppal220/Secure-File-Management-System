"""
Verify Part 1 setup is complete
"""

print("🔍 Testing Part 1 Setup")
print("=" * 60)

tests_passed = 0
tests_failed = 0

# Test 1: Import utils
try:
    from src. utils. logger import logger
    from src.utils.encryption import FileEncryption
    from src. utils.validators import Validators
    print("✅ Utils module imports successful")
    tests_passed += 1
except Exception as e:
    print(f"❌ Utils module import failed: {e}")
    tests_failed += 1

# Test 2: Import database
try:
    from src.database.connection import db_connection
    from src.database.models import UserModel, FileModel
    print("✅ Database module imports successful")
    tests_passed += 1
except Exception as e:
    print(f"❌ Database module import failed: {e}")
    tests_failed += 1

# Test 3: Import auth
try:
    from src.auth.auth_manager import AuthManager
    from src.auth.password_manager import PasswordManager
    from src. auth.two_factor import TwoFactorAuth
    print("✅ Auth module imports successful")
    tests_passed += 1
except Exception as e:
    print(f"❌ Auth module import failed: {e}")
    tests_failed += 1

# Test 4: Test logger
try:
    from src.utils.logger import logger
    logger.info("Test log message")
    print("✅ Logger working")
    tests_passed += 1
except Exception as e:
    print(f"❌ Logger failed: {e}")
    tests_failed += 1

# Test 5: Test encryption
try:
    from src.utils.encryption import FileEncryption
    key = FileEncryption.generate_key()
    data = b"Test data"
    encrypted = FileEncryption.encrypt_data(data, key)
    decrypted = FileEncryption. decrypt_data(encrypted, key)
    assert data == decrypted
    print("✅ Encryption working")
    tests_passed += 1
except Exception as e:
    print(f"❌ Encryption failed: {e}")
    tests_failed += 1

# Test 6: Test validators
try:
    from src.utils.validators import Validators
    valid, msg = Validators.validate_email("test@example.com")
    assert valid == True
    print("✅ Validators working")
    tests_passed += 1
except Exception as e:
    print(f"❌ Validators failed: {e}")
    tests_failed += 1

# Test 7: Test password manager
try:
    from src.auth.password_manager import PasswordManager
    pm = PasswordManager()
    hashed = pm.hash_password("Test123!")
    verified = pm.verify_password("Test123!", hashed)
    assert verified == True
    print("✅ Password manager working")
    tests_passed += 1
except Exception as e:
    print(f"❌ Password manager failed: {e}")
    tests_failed += 1

print("\n" + "=" * 60)
print(f"Tests Passed: {tests_passed}")
print(f"Tests Failed: {tests_failed}")
print("=" * 60)

if tests_failed == 0:
    print("\n🎉 PART 1 SETUP COMPLETE!")
    print("You're ready to move to Part 2!")
else:
    print(f"\n⚠️ {tests_failed} test(s) failed.")
    print("Please add the missing code to the files above.")


# test_part2.py
"""
Test Part 2: Threat Detection & File Operations
"""

print("🔍 Testing Part 2 Setup")
print("=" * 60)

tests_passed = 0
tests_failed = 0

# Test 1: Import threat detection
try:
    from src.threat_detection. malware_scanner import MalwareScanner
    from src.threat_detection.virustotal_scanner import VirusTotalScanner
    print("✅ Threat detection module imports successful")
    tests_passed += 1
except Exception as e:
    print(f"❌ Threat detection import failed: {e}")
    tests_failed += 1

# Test 2: Import file operations
try:
    from src.file_ops. file_manager import FileManager
    print("✅ File operations module imports successful")
    tests_passed += 1
except Exception as e:
    print(f"❌ File operations import failed: {e}")
    tests_failed += 1

# Test 3: Initialize MalwareScanner
try:
    scanner = MalwareScanner()
    print("✅ MalwareScanner initialized")
    tests_passed += 1
except Exception as e:
    print(f"❌ MalwareScanner initialization failed: {e}")
    tests_failed += 1

# Test 4: Initialize FileManager
try:
    file_manager = FileManager()
    print("✅ FileManager initialized")
    tests_passed += 1
except Exception as e:
    print(f"❌ FileManager initialization failed: {e}")
    tests_failed += 1

# Test 5: Check directories created
try:
    from pathlib import Path
    assert Path("uploads").exists()
    assert Path("encrypted_files").exists()
    print("✅ File directories created")
    tests_passed += 1
except Exception as e:
    print(f"❌ Directory check failed: {e}")
    tests_failed += 1

print("\n" + "=" * 60)
print(f"Tests Passed: {tests_passed}")
print(f"Tests Failed: {tests_failed}")
print("=" * 60)

if tests_failed == 0:
    print("\n🎉 PART 2 SETUP COMPLETE!")
    print("Ready to move to Part 3: Streamlit UI!")
else:
    print(f"\n⚠️ {tests_failed} test(s) failed.")
    print("Please check the errors above.")
