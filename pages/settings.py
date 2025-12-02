"""
User settings page
"""
import streamlit as st
from src. auth.auth_manager import AuthManager


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

    col1, col2 = st. columns(2)
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
    """Security settings"""

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

    # 2FA Settings
    st.markdown("### 🔐 Two-Factor Authentication")

    user_data = st.session_state.user_data

    if not user_data.get('two_fa_enabled'):
        st. info(
            "📱 Two-Factor Authentication adds an extra layer of security to your account.")

        if st.button("🔓 Enable 2FA"):
            enable_2fa()
    else:
        st.success("✅ Two-Factor Authentication is enabled")

        if st.button("🔒 Disable 2FA"):
            disable_2fa()


def enable_2fa():
    """Enable 2FA"""

    auth_manager = AuthManager()
    success, message, secret, qr_code = auth_manager. enable_2fa(
        st.session_state.username)

    if success:
        st. success(message)

        # Show QR code
        st.image(qr_code, caption="Scan this QR code with your authenticator app")

        # Show secret (for manual entry)
        with st.expander("📋 Manual Entry Code"):
            st.code(secret)

        # Verification
        st.markdown("### Verify Setup")
        with st.form("verify_2fa"):
            token = st.text_input(
                "Enter 6-digit code from your app", max_chars=6)
            verify = st.form_submit_button("✅ Verify and Enable")

        if verify:
            success, msg = auth_manager.confirm_2fa_setup(
                st.session_state. username, token)

            if success:
                st.success(f"✅ {msg}")
                st.session_state.user_data['two_fa_enabled'] = True
                st.rerun()
            else:
                st.error(f"❌ {msg}")
    else:
        st.error(f"❌ {message}")


def disable_2fa():
    """Disable 2FA"""

    with st.form("disable_2fa_form"):
        st.warning("⚠️ This will reduce your account security")
        password = st.text_input(
            "Enter your password to confirm", type="password")
        submit = st.form_submit_button("Disable 2FA")

    if submit:
        if not password:
            st. error("⚠️ Password is required")
            return

        auth_manager = AuthManager()
        success, message = auth_manager.disable_2fa(
            st.session_state.username, password)

        if success:
            st. success(f"✅ {message}")
            st.session_state.user_data['two_fa_enabled'] = False
            st.rerun()
        else:
            st.error(f"❌ {message}")


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

    # Display logs
    for log in logs:
        col1, col2, col3 = st.columns([2, 3, 2])

        with col1:
            timestamp = log['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
            st.caption(timestamp)

        with col2:
            action = log['action']
            st.write(f"**{action. upper()}**")
            if log. get('details'):
                st. caption(log['details'])

        with col3:
            status = log['status']
            if status == 'success':
                st.success("✅ Success")
            elif status == 'failed':
                st.error("❌ Failed")
            else:
                st.warning("⚠️ " + status)

        st.markdown("---")
