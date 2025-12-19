"""
File dashboard - View and manage files
"""
import streamlit as st
from src.file_ops.file_manager import FileManager
from datetime import datetime
import humanize


def dashboard_page():
    """Main file dashboard"""

    st.title("📁 My Files")
    st.markdown("---")

    file_manager = FileManager()

    # Get user files
    files = file_manager.list_user_files(st.session_state.username)

    if not files:
        st.info("📂 No files yet.Upload your first file!")
        if st.button("⬆️ Go to Upload Page"):
            st.session_state.navigation = "⬆️ Upload File"
            st.rerun()
        return

    # Filter options
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        filter_type = st.selectbox(
            "Filter", ["All Files", "My Files", "Shared with Me"])
    with col2:
        search = st.text_input(
            "🔍 Search files", placeholder="Search by filename...")
    with col3:
        st.metric("Total Files", len(files))

    # Apply filters
    filtered_files = files

    if filter_type == "My Files":
        filtered_files = [f for f in files if f['access_type'] == 'owner']
    elif filter_type == "Shared with Me":
        filtered_files = [f for f in files if f['access_type'] == 'shared']

    if search:
        filtered_files = [
            f for f in filtered_files if search.lower() in f['filename'].lower()]

    st.markdown(f"**Showing {len(filtered_files)} file(s)**")
    st.markdown("---")

    # Display files
    for file in filtered_files:
        display_file_card(file, file_manager)


def display_file_card(file: dict, file_manager: FileManager):
    """Display a file card with actions"""

    with st.container():
        col1, col2, col3, col4 = st.columns([3, 2, 2, 2])

        with col1:
            # File icon based on type
            icon = get_file_icon(file['filename'])
            st.markdown(f"### {icon} {file['filename']}")

            # File info
            size_mb = file['file_size'] / (1024 * 1024)
            st.caption(f"📊 Size: {size_mb:.2f} MB")

            # Upload time
            if isinstance(file['uploaded_at'], datetime):
                uploaded = humanize.naturaltime(
                    datetime.utcnow() - file['uploaded_at'])
            else:
                uploaded = "Unknown"
            st.caption(f"🕐 Uploaded: {uploaded}")

        with col2:
            st.write("")  # Spacing
            st.write("")
            if file['access_type'] == 'owner':
                st.success("👑 Owner")
            else:
                st.info("🔗 Shared")
                if 'permissions' in file:
                    st.caption(
                        f"Permissions: {', '.join(file['permissions'])}")

        with col3:
            st.write("")  # Spacing
            # Download button
            if st.button("⬇️ Download", key=f"download_{file['file_id']}"):
                download_file(file['file_id'], file['filename'], file_manager)

            # View metadata
            if st.button("ℹ️ Details", key=f"details_{file['file_id']}"):
                st.session_state[f"viewing_{file['file_id']}"] = True
                st.rerun()

        with col4:
            st.write("")  # Spacing
            # Share button (only for owners)
            if file['access_type'] == 'owner':
                if st.button("🔗 Share", key=f"share_{file['file_id']}"):
                    st.session_state[f"sharing_{file['file_id']}"] = True
                    st.rerun()

                # Delete button
                if st.button("🗑️ Delete", key=f"delete_{file['file_id']}"):
                    delete_file(file['file_id'], file_manager)

        # Show details dialog if active
        if st.session_state.get(f"viewing_{file['file_id']}", False):
            show_file_details(file['file_id'], file_manager)

        # Sharing dialog
        if st.session_state.get(f"sharing_{file['file_id']}", False):
            show_share_dialog(file['file_id'], file_manager)

        st.markdown("---")


def download_file(file_id: str, filename: str, file_manager: FileManager):
    """Download a file"""

    with st.spinner("Downloading and decrypting file..."):
        success, message, file_data, _ = file_manager.download_file(
            file_id,
            st.session_state.username
        )

    if success:
        st.download_button(
            label="💾 Click to Download",
            data=file_data,
            file_name=filename,
            mime="application/octet-stream",
            key=f"dl_btn_{file_id}"
        )
        st.success("✅ File ready for download!")
    else:
        st.error(f"❌ {message}")


def show_file_details(file_id: str, file_manager: FileManager):
    """Show detailed file metadata"""

    success, message, metadata = file_manager.get_file_metadata(
        file_id,
        st.session_state.username
    )

    if success:
        st.info("📋 **File Details**")

        col1, col2, col3 = st.columns([1, 1, 1])

        with col1:
            st.write(f"**Filename:** {metadata['filename']}")
            st.write(f"**Size:** {metadata['file_size'] / (1024*1024):.2f} MB")
            st.write(f"**Owner:** {metadata['owner']}")

        with col2:
            st.write(f"**MIME Type:** {metadata['mime_type']}")
            st.write(f"**Access Count:** {metadata['access_count']}")
            st.write(f"**Threat Scan:** {metadata['threat_scan_status']}")

        with col3:
            st.write(f"**Shared:** {'Yes' if metadata['is_shared'] else 'No'}")
            if metadata.get('tags'):
                st.write(f"**Tags:** {', '.join(metadata['tags'])}")
            st.write(f"**File ID:** `{metadata['file_id'][:8]}...`")

        # Show shared users list if owner and file is shared
        if metadata['owner'] == st.session_state.username and metadata.get('is_shared'):
            shared_with = metadata.get('shared_with', [])
            if shared_with:
                st.markdown("---")
                st.write(f"**👥 Shared With {len(shared_with)} user(s):**")

                for idx, shared_user in enumerate(shared_with):
                    col_a, col_b, col_c = st.columns([3, 5, 2])
                    with col_a:
                        st.write(f"👤 **{shared_user['username']}**")
                    with col_b:
                        perms = ', '.join(shared_user.get('permissions', []))
                        st.caption(f"🔑 {perms}")
                    with col_c:
                        if st.button("🚫 Revoke", key=f"revoke_{file_id}_{idx}_{shared_user['username']}"):
                            success_rev, msg = file_manager.unshare_file(
                                file_id,
                                st.session_state.username,
                                shared_user['username']
                            )
                            if success_rev:
                                st.success(msg)
                                st.session_state[f"viewing_{file_id}"] = False
                                st.rerun()
                            else:
                                st.error(msg)

        # Close button
        if st.button("❌ Close", key=f"close_details_{file_id}", use_container_width=True):
            st.session_state[f"viewing_{file_id}"] = False
            st.rerun()

    else:
        st.error(f"❌ {message}")


def show_share_dialog(file_id: str, file_manager: FileManager):
    """Show file sharing dialog"""

    with st.form(f"share_form_{file_id}"):
        st.subheader("🔗 Share File")

        share_with = st.text_input(
            "Share with username", placeholder="Enter username")

        st.write("**Permissions:**")
        col1, col2 = st.columns(2)
        with col1:
            perm_read = st.checkbox("Read", value=True)
            perm_download = st.checkbox("Download", value=True)
        with col2:
            perm_write = st.checkbox("Write")
            perm_share = st.checkbox("Share")

        col_a, col_b = st.columns(2)
        with col_a:
            submit = st.form_submit_button("✅ Share", use_container_width=True)
        with col_b:
            cancel = st.form_submit_button(
                "❌ Cancel", use_container_width=True)

    if submit:
        if not share_with:
            st.error("⚠️ Please enter a username")
            return

        # Build permissions list
        permissions = []
        if perm_read:
            permissions.append('read')
        if perm_download:
            permissions.append('download')
        if perm_write:
            permissions.append('write')
        if perm_share:
            permissions.append('share')

        success, message = file_manager.share_file(
            file_id,
            st.session_state.username,
            share_with,
            permissions
        )

        if success:
            st.success(f"✅ {message}")
            st.session_state[f"sharing_{file_id}"] = False
            st.rerun()
        else:
            st.error(f"❌ {message}")

    if cancel:
        st.session_state[f"sharing_{file_id}"] = False
        st.rerun()


def delete_file(file_id: str, file_manager: FileManager):
    """Delete a file"""

    if st.session_state.get(f"confirm_delete_{file_id}", False):
        success, message = file_manager.delete_file(
            file_id, st.session_state.username)

        if success:
            st.success(f"✅ {message}")
            st.session_state[f"confirm_delete_{file_id}"] = False
            st.rerun()
        else:
            st.error(f"❌ {message}")
    else:
        st.session_state[f"confirm_delete_{file_id}"] = True
        st.warning("⚠️ Click Delete again to confirm")


def get_file_icon(filename: str) -> str:
    """Get emoji icon for file type"""
    ext = filename.split('.')[-1].lower()

    icons = {
        'pdf': '📕',
        'doc': '📘', 'docx': '📘',
        'xls': '📗', 'xlsx': '📗',
        'ppt': '📙', 'pptx': '📙',
        'txt': '📄',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
        'zip': '📦', 'rar': '📦', '7z': '📦',
        'mp4': '🎥', 'avi': '🎥', 'mkv': '🎥',
        'mp3': '🎵', 'wav': '🎵',
    }

    return icons.get(ext, '📄')
