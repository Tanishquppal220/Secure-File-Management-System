"""
Test VirusTotal API integration
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from src.threat_detection.virustotal_scanner import VirusTotalScanner

load_dotenv()


def test_virustotal():
    """Test VirusTotal scanner"""

    print("🛡️ Testing VirusTotal Malware Scanner")
    print("=" * 60)

    # Check API key
    api_key = os.getenv('VIRUSTOTAL_API_KEY')

    if not api_key:
        print("❌ VIRUSTOTAL_API_KEY not found in .env file")
        print("\nPlease add your VirusTotal API key to .env:")
        print("VIRUSTOTAL_API_KEY=your_api_key_here")
        return

    print(f"API Key: {api_key[:16]}... {api_key[-16:]}")
    print("=" * 60)

    # Create scanner
    scanner = VirusTotalScanner()

    # Create a test file
    test_file = Path("test_clean_file.txt")
    test_file.write_text(
        "This is a clean test file for malware scanning.\nCreated for Secure File Management System testing.")

    print(f"\n1. Created test file: {test_file}")
    print(f"   Size: {test_file.stat(). st_size} bytes")

    # Scan the file
    print("\n2. Uploading to VirusTotal for scanning...")
    print("   ⏳ This may take 15-30 seconds...")
    print("   (File is being scanned by 70+ antivirus engines)")

    is_safe, result = scanner.scan_file(str(test_file))

    print("\n" + "=" * 60)
    print("📊 SCAN RESULTS")
    print("=" * 60)

    print(f"\n✓ Status: {result. get('status')}")
    print(f"✓ Safe: {'YES ✅' if is_safe else 'NO ⚠️'}")
    print(f"✓ Threat Level: {result.get('threat_level', 'unknown'). upper()}")
    print(f"\n💬 {result.get('message')}")

    if result. get('status') == 'completed':
        print(f"\n📈 Detection Statistics:")
        print(f"   Malicious:  {result.get('malicious', 0):>3} engines")
        print(f"   Suspicious: {result.get('suspicious', 0):>3} engines")
        print(f"   Harmless:   {result.get('harmless', 0):>3} engines")
        print(f"   Undetected: {result.get('undetected', 0):>3} engines")
        print(f"   ─────────────────")
        print(f"   Total:      {result.get('total_scans', 0):>3} engines")

    # Clean up
    test_file. unlink()
    print(f"\n3. ✓ Cleaned up test file")

    print("\n" + "=" * 60)
    if is_safe and result.get('status') == 'completed':
        print("✅ SUCCESS!  VirusTotal integration is working perfectly!")
        print("=" * 60)
        print("\n🎉 You're ready to use malware scanning in your app!")
        print("\nAPI Limits:")
        print("  • 500 requests per day")
        print("  • 4 requests per minute")
        print("  • Perfect for your college project!")
    else:
        print("⚠️ Please check the results above")
        print("=" * 60)


if __name__ == "__main__":
    test_virustotal()
