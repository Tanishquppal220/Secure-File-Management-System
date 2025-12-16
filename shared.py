"""
Shared files page
"""
import streamlit as st
from src.file_ops.file_manager import FileManager


def shared_files_page():
    """Display files shared with the user"""

    st.title("🔗 Shared Files")
    st.markdown("---")

    file_manager = FileManager()

    # Get all files
    all_files = file_manager.list_user_files(st.session_state.username)

    # Filter shared files
    shared_files = [f for f in all_files if f['access_type'] == 'shared']

    if not shared_files:
        st.info("📂 No files have been shared with you yet.")
        return

    st.write(f"**{len(shared_files)} file(s) shared with you**")
    st.markdown("---")

    # Display shared files
    for file in shared_files:
        with st.container():
            col1, col2, col3 = st.columns([3, 2, 2])

            with col1:
                st.markdown(f"### 📄 {file['filename']}")
                st.caption(f"👤 Owner: {file['owner']}")
                size_mb = file['file_size'] / (1024 * 1024)
                st.caption(f"📊 Size: {size_mb:.2f} MB")

            with col2:
                st. write("")
                st.write("")
                permissions = file. get('permissions', [])
                st.write("**Your Permissions:**")
                for perm in permissions:
                    st.caption(f"✓ {perm. capitalize()}")

            with col3:
                st.write("")
                # Download if permitted
                if 'download' in file. get('permissions', []) or 'read' in file.get('permissions', []):
                    if st.button("⬇️ Download", key=f"dl_shared_{file['file_id']}"):
                        download_shared_file(
                            file['file_id'], file['filename'], file_manager)
                else:
                    st.caption("❌ No download permission")

            st.markdown("---")


def download_shared_file(file_id: str, filename: str, file_manager: FileManager):
    """Download a shared file"""

    with st.spinner("Downloading file... "):
        success, message, file_data, _ = file_manager.download_file(
            file_id,
            st.session_state. username
        )

    if success:
        st.download_button(
            label="💾 Click to Download",
            data=file_data,
            file_name=filename,
            mime="application/octet-stream",
            key=f"dl_btn_shared_{file_id}"
        )
        st.success("✅ File ready for download!")
    else:
        st.error(f"❌ {message}")
