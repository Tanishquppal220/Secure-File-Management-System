"""
Secure File Management System - Main Streamlit Application
"""
import streamlit as st
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="Secure File Management System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
    }
    . sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        padding-bottom: 2rem;
    }
    . stButton>button {
        width: 100%;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0. 5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
    }
    [data-testid="stSidebarNav"] {
        display: none !important;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    st. session_state.username = None
    st.session_state.user_data = None
    st.session_state.awaiting_2fa = False

# Main app logic


def main():
    """Main application controller"""

    if not st.session_state.authenticated:
        # Show authentication page
        show_auth_page()
    else:
        # Show main application
        show_main_app()


def show_auth_page():
    """Display authentication page"""
    from pages.auth import auth_page
    auth_page()


def show_main_app():
    """Display main application with sidebar navigation"""

    # Initialize navigation if not set
    if 'navigation' not in st.session_state:
        st.session_state.navigation = "📁 My Files"

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👤 Welcome, {st.session_state.username}!")
        st.markdown("---")

        # Navigation
        page = st.radio(
            "Navigation",
            ["📁 My Files", "⬆️ Upload File",
                "🔗 Shared Files", "⚙️ Settings"],
            index=["📁 My Files", "⬆️ Upload File",
                   "🔗 Shared Files", "⚙️ Settings"].index(st.session_state.navigation) if st.session_state.navigation in ["📁 My Files", "⬆️ Upload File", "🔗 Shared Files", "⚙️ Settings"] else 0,
            label_visibility="collapsed"
        )

        # Update navigation state
        st.session_state.navigation = page

        st.markdown("---")
        
        # Logout button
        if st.button("🚪 Logout", use_container_width=True):
            logout()
        
        st.markdown("---")
        st.caption("🔐 Secure File Management System")
        st.caption("v1.0. 0 | 2025")

    # Main content area
    if st.session_state.navigation == "📁 My Files":
        from pages.dashboard import dashboard_page
        dashboard_page()

    elif st.session_state.navigation == "⬆️ Upload File":
        from pages.upload import upload_page
        upload_page()

    elif st.session_state.navigation == "🔗 Shared Files":
        from pages.shared import shared_files_page
        shared_files_page()

    elif st.session_state.navigation == "⚙️ Settings":
        from pages.settings import settings_page
        settings_page()


def logout():
    """Handle user logout"""
    from src.auth.auth_manager import AuthManager

    auth_manager = AuthManager()
    auth_manager.logout(st.session_state.username)

    # Clear all session state including navigation
    for key in list(st.session_state.keys()):
        del st.session_state[key]

    # Reset authentication state
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.user_data = None
    st.session_state.awaiting_2fa = False

    st.success("Logged out successfully!")
    st.rerun()


if __name__ == "__main__":
    main()
