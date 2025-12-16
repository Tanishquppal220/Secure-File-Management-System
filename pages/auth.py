"""
Authentication page - Login, Register, 2FA
"""
import streamlit as st
from src.auth.auth_manager import AuthManager
from src.utils.logger import logger


def auth_page():
    """Authentication page with login and registration"""

    st.markdown('<div class="main-header">🔐 Secure File Management System</div>',
                unsafe_allow_html=True)
    st.markdown('<div class="sub-header">Secure.  Encrypted. Protected.</div>',
                unsafe_allow_html=True)

    # Tabs for Login and Register
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])

    with tab1:
        login_form()

    with tab2:
        register_form()


def login_form():
    """Login form"""

    st.subheader("Login to Your Account")

    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input(
            "Password", type="password", placeholder="Enter your password")

        col1, col2 = st. columns([1, 1])
        with col1:
            submit = st.form_submit_button("🔓 Login", use_container_width=True)
        with col2:
            st.form_submit_button("🔄 Clear", use_container_width=True)

    if submit:
        if not username or not password:
            st.error("⚠️ Please enter both username and password")
            return

        # Authenticate
        auth_manager = AuthManager()
        success, message, user_data = auth_manager. login(username, password)

        if success:
            if message == "2fa_required":
                # 2FA required
                st.session_state.awaiting_2fa = True
                st.session_state.temp_username = username
                st. session_state.user_data = user_data
                st.info("🔐 Two-Factor Authentication Required")
                st.rerun()
            else:
                # Login successful
                st.session_state.authenticated = True
                st.session_state.username = username
                st. session_state.user_data = user_data
                st.success(f"✅ {message}")
                logger.info(f"User logged in: {username}")
                st.rerun()
        else:
            st.error(f"❌ {message}")

    # 2FA verification if needed
    if st.session_state.get('awaiting_2fa', False):
        show_2fa_verification()


def show_2fa_verification():
    """Show 2FA verification form"""

    st.markdown("---")
    st.subheader("🔐 Two-Factor Authentication")
    st. info("Enter the 6-digit code from your authenticator app")

    with st.form("2fa_form"):
        token = st.text_input("6-Digit Code", max_chars=6,
                              placeholder="000000")
        submit = st.form_submit_button("✅ Verify", use_container_width=True)

    if submit:
        if len(token) != 6:
            st.error("⚠️ Please enter a 6-digit code")
            return

        auth_manager = AuthManager()
        success, message, user_data = auth_manager. verify_2fa_and_login(
            st.session_state.temp_username,
            token
        )

        if success:
            st.session_state.authenticated = True
            st.session_state.username = st.session_state.temp_username
            st.session_state.user_data = user_data
            st. session_state.awaiting_2fa = False
            st.success(f"✅ {message}")
            st.rerun()
        else:
            st.error(f"❌ {message}")


def register_form():
    """Registration form"""

    st. subheader("Create New Account")

    with st.form("register_form"):
        username = st.text_input(
            "Username", placeholder="Choose a username (3-20 characters)")
        email = st.text_input("Email", placeholder="your.email@example.com")
        password = st.text_input(
            "Password", type="password", placeholder="Min 8 characters, mixed case, numbers, symbols")
        password_confirm = st.text_input(
            "Confirm Password", type="password", placeholder="Re-enter your password")

        st.caption(
            "Password requirements: Min 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character")

        submit = st.form_submit_button("📝 Register", use_container_width=True)

    if submit:
        # Validation
        if not all([username, email, password, password_confirm]):
            st.error("⚠️ All fields are required")
            return

        if password != password_confirm:
            st.error("⚠️ Passwords do not match")
            return

        # Register user
        auth_manager = AuthManager()
        success, message = auth_manager.register_user(
            username, email, password)

        if success:
            st.success(f"✅ {message}")
            st.info("👉 Please login with your credentials")
            logger.info(f"New user registered: {username}")
        else:
            st.error(f"❌ {message}")
