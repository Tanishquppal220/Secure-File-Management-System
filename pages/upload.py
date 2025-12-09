"""
File upload page
"""
import streamlit as st
from src.file_ops.file_manager import FileManager
from io import BytesIO


def upload_page():
    """File upload page"""

    st.title("⬆️ Upload File")
    st.markdown("---")

    file_manager = FileManager()

    # Upload form
    with st.form("upload_form", clear_on_submit=True):
        st.subheader("📤 Select File to Upload")

        uploaded_file = st.file_uploader(
            "Choose a file",
            type=file_manager.allowed_extensions,
            help=f"Allowed types: {', '.join(file_manager.allowed_extensions)}"
        )

        # Tags
        tags_input = st.text_input(
            "Tags (optional)",
            placeholder="e.g., work, important, 2025",
            help="Separate tags with commas"
        )

        # Malware scan option
        scan_malware = st.checkbox(
            "🛡️ Scan for malware (recommended)", value=True)

        if scan_malware:
            st. info(
                "ℹ️ File will be scanned using VirusTotal API.  This may take 15-30 seconds.")

        # Submit
        submit = st.form_submit_button(
            "🚀 Upload File", use_container_width=True)

    if submit and uploaded_file:
        # Parse tags
        tags = []
        if tags_input:
            tags = [tag.strip()
                    for tag in tags_input.split(',') if tag.strip()]

        # Show file info
        st.write("**File Information:**")
        col1, col2 = st.columns(2)
        with col1:
            st.write(f"📄 **Name:** {uploaded_file.name}")
            st.write(f"📊 **Size:** {uploaded_file.size / (1024*1024):.2f} MB")
        with col2:
            st. write(f"📑 **Type:** {uploaded_file.type}")
            if tags:
                st.write(f"🏷️ **Tags:** {', '.join(tags)}")

        # Upload
        with st.spinner("Uploading and encrypting file..." + (" (Scanning for malware... )" if scan_malware else "")):
            # Convert to BytesIO
            file_obj = BytesIO(uploaded_file.read())

            success, message, file_id = file_manager.upload_file(
                file_obj,
                uploaded_file.name,
                st.session_state.username,
                tags,
                scan_malware
            )

        if success:
            st.success(f"✅ {message}")
            # st.balloons()

            # Show file ID
            with st.expander("📋 File Details"):
                st.code(f"File ID: {file_id}")
                st.write("Your file has been encrypted and stored securely.")

            # Navigation buttons
            col1, col2 = st.columns(2)
            with col1:
                if st.button("📁 View My Files"):
                    st.session_state.navigation = "📁 My Files"
                    st.rerun()
            with col2:
                if st.button("⬆️ Upload Another"):
                    st.rerun()
        else:
            st.error(f"❌ {message}")

            if "threat detected" in message. lower():
                st.warning(
                    "🛡️ **Security Alert:** The file was blocked for your protection.")

    elif submit:
        st.warning("⚠️ Please select a file to upload")

    # Upload guidelines
    st.markdown("---")
    with st.expander("📖 Upload Guidelines"):
        st. markdown(f"""
        **File Requirements:**
        - Maximum file size: {file_manager.max_file_size / (1024*1024):.0f} MB
        - Allowed file types: {', '.join(file_manager.allowed_extensions)}
        
        **Security Features:**
        - All files are encrypted using AES-256
        - Optional malware scanning with VirusTotal
        - Secure storage with access control
        - Activity logging for audit trail
        
        **Tips:**
        - Use descriptive filenames
        - Add relevant tags for easy searching
        - Enable malware scanning for unknown files
        - Files can be shared with other users after upload
        """)
