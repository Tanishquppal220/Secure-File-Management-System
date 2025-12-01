"""
Test Gmail SMTP configuration
"""
import os
import smtplib
from email. mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()


def test_email_config():
    """Test email sending capability"""

    print("📧 Testing Gmail SMTP Configuration")
    print("=" * 60)

    # Get credentials
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT'))
    sender_email = os. getenv('SENDER_EMAIL')
    sender_password = os. getenv('SENDER_PASSWORD')

    print(f"SMTP Server: {smtp_server}")
    print(f"SMTP Port: {smtp_port}")
    print(f"Sender Email: {sender_email}")
    print(
        f"Password: {'*' * len(sender_password) if sender_password else 'NOT SET'}")
    print("=" * 60)

    # Remove spaces from app password (if any)
    if sender_password:
        sender_password = sender_password.replace(' ', '')

    try:
        # Create message
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = sender_email  # Send to yourself for testing
        message['Subject'] = "Test Email - Secure File Management System"

        body = """
        This is a test email from your Secure File Management System.
        
        If you receive this email, your email configuration is working correctly! 
        
        Configuration:
        - SMTP Server: {}
        - SMTP Port: {}
        - Sender: {}
        
        ✅ Email system is ready for 2FA codes!
        """.format(smtp_server, smtp_port, sender_email)

        message.attach(MIMEText(body, 'plain'))

        # Connect to server
        print("\n1. Connecting to SMTP server...")
        server = smtplib.SMTP(smtp_server, smtp_port)

        print("2. Starting TLS encryption...")
        server.starttls()

        print("3. Logging in...")
        server.login(sender_email, sender_password)

        print("4. Sending test email...")
        server.send_message(message)

        print("5. Closing connection...")
        server.quit()

        print("\n" + "=" * 60)
        print("✅ SUCCESS!  Test email sent successfully!")
        print("=" * 60)
        print(f"\n📬 Check your inbox at: {sender_email}")
        print("You should receive a test email within a few seconds.")

        return True

    except smtplib.SMTPAuthenticationError:
        print("\n" + "=" * 60)
        print("❌ AUTHENTICATION FAILED")
        print("=" * 60)
        print("\nPossible issues:")
        print("1. App password is incorrect")
        print("2. App password has spaces (remove them)")
        print("3. 2-Step Verification is not enabled")
        print("4. Using regular password instead of app password")
        print("\nSolution:")
        print("- Generate a new app password")
        print("- Make sure to use the 16-character app password, not your regular Gmail password")
        return False

    except Exception as e:
        print("\n" + "=" * 60)
        print("❌ ERROR")
        print("=" * 60)
        print(f"\n{type(e).__name__}: {e}")
        return False


if __name__ == "__main__":
    test_email_config()
