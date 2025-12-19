"""
User settings page - FIXED VERSION
"""
import streamlit as st
from src.auth.auth_manager import AuthManager


def settings_page():
    """User settings and profile management"""

    st.title("⚙️ Settings")
    st.markdown("---")

    tab1, tab2, tab3 = st.tabs(["👤 Profile", "🔐 Security", "📊 Activity"])

    with tab1:
        profile_settings()

    with tab2:
        security_settings()

    with tab3:
        activity_logs()


def profile_settings():
    """Profile settings"""

    st.subheader("Profile Information")

    user_data = st.session_state.user_data

    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Username:** {st.session_state.username}")
        st.write(f"**Email:** {user_data.get('email', 'N/A')}")
    with col2:
        st.write(f"**Role:** {user_data.get('role', 'user')}")
        st.write(
            f"**2FA Status:** {'✅ Enabled' if user_data.get('two_fa_enabled') else '❌ Disabled'}")

    st.markdown("---")
    st.info("ℹ️ Contact administrator to update profile information.")


def security_settings():
    """Security settings - FIXED VERSION"""

    st.subheader("Security Settings")

    # Change password
    st.markdown("### 🔑 Change Password")

    with st.form("change_password_form"):
        old_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input(
            "Confirm New Password", type="password")

        submit = st.form_submit_button("Update Password")

    if submit:
        if not all([old_password, new_password, confirm_password]):
            st.error("⚠️ All fields are required")
        elif new_password != confirm_password:
            st.error("⚠️ New passwords do not match")
        else:
            auth_manager = AuthManager()
            success, message = auth_manager.change_password(
                st.session_state.username,
                old_password,
                new_password
            )

            if success:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")

    st.markdown("---")

    # 2FA Settings - FIXED
    st.markdown("### 🔐 Two-Factor Authentication")

    # Refresh user data from session
    user_data = st.session_state.user_data

    # Check if we're in 2FA setup mode
    if st.session_state.get('setting_up_2fa', False):
        show_2fa_setup_process()
    elif st.session_state.get('disabling_2fa', False):
        show_2fa_disable_process()
    else:
        # Show 2FA status and enable/disable buttons
        if not user_data.get('two_fa_enabled'):
            st.info(
                "📱 Two-Factor Authentication adds an extra layer of security to your account.")

            if st.button("🔓 Enable 2FA", key="btn_enable_2fa"):
                st.session_state.setting_up_2fa = True
                st.rerun()
        else:
            st.success("✅ Two-Factor Authentication is enabled")

            if st.button("🔒 Disable 2FA", key="btn_disable_2fa"):
                st.session_state.disabling_2fa = True
                st.rerun()


def show_2fa_setup_process():
    """Show 2FA setup process - FIXED to prevent double execution"""

    st.info("🔐 Setting up Two-Factor Authentication...")

    # Initialize 2FA data in session state if not present
    if 'twofa_secret' not in st.session_state:
        # Only call enable_2fa once
        auth_manager = AuthManager()
        success, message, secret, qr_code = auth_manager.enable_2fa(
            st.session_state.username)

        if success:
            # Store in session state
            st.session_state.twofa_secret = secret
            st.session_state.twofa_qr_code = qr_code
            st.session_state.twofa_message = message
        else:
            st.error(f"❌ {message}")
            if st.button("« Back"):
                st.session_state.setting_up_2fa = False
                st.rerun()
            return

    # Display QR code and setup instructions
    st.success(st.session_state.twofa_message)

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("#### Step 1: Scan QR Code")
        st.image(st.session_state.twofa_qr_code,
                 caption="Scan with Google Authenticator, Authy, or similar app", width=300)

    with col2:
        st.markdown("#### Step 2: Manual Entry")
        st.info("If you can't scan the QR code, enter this secret manually:")
        st.code(st.session_state.twofa_secret)

        st.markdown("#### Recommended Apps:")
        st.markdown("""
        - Google Authenticator
        - Microsoft Authenticator
        - Authy
        - 1Password
        """)

    # Verification form
    st.markdown("---")
    st.markdown("#### Step 3: Verify Setup")

    with st.form("verify_2fa_setup"):
        token = st.text_input(
            "Enter 6-digit code from your app", max_chars=6, placeholder="000000")

        col_a, col_b = st.columns(2)
        with col_a:
            verify = st.form_submit_button(
                "✅ Verify and Enable", use_container_width=True)
        with col_b:
            cancel = st.form_submit_button(
                "❌ Cancel", use_container_width=True)

    if verify:
        if len(token) != 6 or not token.isdigit():
            st.error("⚠️ Please enter a valid 6-digit code")
        else:
            auth_manager = AuthManager()
            success, msg = auth_manager.confirm_2fa_setup(
                st.session_state.username, token)

            if success:
                st.success(f"✅ {msg}")
                st.balloons()

                # Update user data
                st.session_state.user_data['two_fa_enabled'] = True

                # Clear 2FA setup data
                del st.session_state.twofa_secret
                del st.session_state.twofa_qr_code
                del st.session_state.twofa_message
                st.session_state.setting_up_2fa = False

                st.info("Refreshing...")
                st.rerun()
            else:
                st.error(f"❌ {msg}")
                st.warning("💡 Make sure your device time is synchronized")

    if cancel:
        # Clear 2FA setup data
        if 'twofa_secret' in st.session_state:
            del st.session_state.twofa_secret
        if 'twofa_qr_code' in st.session_state:
            del st.session_state.twofa_qr_code
        if 'twofa_message' in st.session_state:
            del st.session_state.twofa_message
        st.session_state.setting_up_2fa = False
        st.rerun()


def show_2fa_disable_process():
    """Show 2FA disable process"""

    st.warning("⚠️ Disabling Two-Factor Authentication")
    st.markdown(
        "This will reduce your account security.You'll need to enter your password to confirm.")

    with st.form("disable_2fa_form"):
        password = st.text_input(
            "Enter your password to confirm", type="password")

        col_a, col_b = st.columns(2)
        with col_a:
            submit = st.form_submit_button(
                "🔓 Disable 2FA", use_container_width=True)
        with col_b:
            cancel = st.form_submit_button(
                "❌ Cancel", use_container_width=True)

    if submit:
        if not password:
            st.error("⚠️ Password is required")
        else:
            auth_manager = AuthManager()
            success, message = auth_manager.disable_2fa(
                st.session_state.username, password)

            if success:
                st.success(f"✅ {message}")
                st.session_state.user_data['two_fa_enabled'] = False
                st.session_state.disabling_2fa = False
                st.rerun()
            else:
                st.error(f"❌ {message}")

    if cancel:
        st.session_state.disabling_2fa = False
        st.rerun()


def activity_logs():
    """Display user activity logs"""

    st.subheader("Recent Activity")

    from src.database.connection import db_connection

    # Get recent logs
    logs = list(db_connection.db.access_logs.find(
        {"user": st.session_state.username}
    ).sort("timestamp", -1).limit(20))

    if not logs:
        st.info("No activity logs found.")
        return

    # Display logs in a table format
    for i, log in enumerate(logs):
        with st.expander(f"📋 {log['action'].upper()} - {log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}", expanded=(i == 0)):
            col1, col2 = st.columns(2)

            with col1:
                st.write(f"**Action:** {log['action']}")
                st.write(f"**Status:** {log['status']}")
                st.write(
                    f"**Time:** {log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")

            with col2:
                if log.get('file_id'):
                    st.write(f"**File ID:** `{log['file_id']}`")
                if log.get('details'):
                    st.write(f"**Details:** {log['details']}")
                if log.get('ip_address'):
                    st.write(f"**IP Address:** {log['ip_address']}")

            # Status indicator
            if log['status'] == 'success':
                st.success("✅ Success")
            elif log['status'] == 'failed':
                st.error("❌ Failed")
            else:
                st.warning(f"⚠️ {log['status']}")
