# streamlit_app.py

import streamlit as st
import base64
import json
import os
from io import BytesIO
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# App title
st.set_page_config(page_title="GCM(224 bits) using PBKDF-2", layout="wide")

st.title("GCM(224 bits) Encryption using PBKDF-2")

# Tabs for Encryption, Decryption, Info
tabs = st.tabs(["🔏 Encrypt", "🔓 Decrypt", "ℹ️ Info"])

# === Encrypt Tab ===
with tabs[0]:
    st.header("Encrypt a File")

    uploaded_file = st.file_uploader("Upload file to encrypt", type=None)
    password = st.text_input("Enter password", type="password", max_chars=512)
    show_password = st.checkbox("Show password")
    if show_password:
        st.text(f"🔑 Password: {password}")

    if st.button("Encrypt File") and uploaded_file and password:
        try:
            # Read uploaded file
            data = uploaded_file.read()

            # Derive key
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

            # Encrypt using AES-GCM
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)

            # Store metadata
            file_ext = os.path.splitext(uploaded_file.name)[1]
            metadata = {
                "file_extension": file_ext,
                "salt": base64.b64encode(salt).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "iterations": 100000
            }
            metadata_json = json.dumps(metadata).encode()

            encrypted_blob = metadata_json + b"\n\n" + ciphertext

            # Download button
            st.success("File encrypted successfully!")
            encrypted_filename = uploaded_file.name + ".a7"
            st.download_button(
                label="Download Encrypted File",
                data=encrypted_blob,
                file_name=encrypted_filename,
                mime="application/octet-stream"
            )
        except Exception as e:
            st.error(f"Encryption failed: {e}")

# === Decrypt Tab ===
with tabs[1]:
    st.header("Decrypt a File")

    encrypted_file = st.file_uploader("Upload .a7 file to decrypt", type=["a7"])
    password = st.text_input("Enter password", type="password", key="decrypt_pw")
    show_password = st.checkbox("Show password", key="decrypt_show")
    if show_password:
        st.text(f"🔑 Password: {password}")

    if st.button("Decrypt File") and encrypted_file and password:
        try:
            content = encrypted_file.read()
            metadata_raw, ciphertext = content.split(b"\n\n", 1)
            metadata = json.loads(metadata_raw.decode())

            salt = base64.b64decode(metadata["salt"])
            nonce = base64.b64decode(metadata["nonce"])
            iterations = metadata.get("iterations", 100000)
            file_ext = metadata["file_extension"]

            # Re-derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

            # Decrypt
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            st.success("Decryption successful!")

            decrypted_filename = os.path.splitext(encrypted_file.name)[0] + file_ext
            st.download_button(
                label="Download Decrypted File",
                data=plaintext,
                file_name=decrypted_filename,
                mime="application/octet-stream"
            )
        except InvalidTag:
            st.error("Incorrect password or corrupted file.")
        except Exception as e:
            st.error(f"Decryption failed: {e}")

# === Info Tab ===
with tabs[2]:
    st.header("GCM(224 bits) Encryption & Decryption using PBKDF-2")

    st.markdown("""
    ### 🔐 Encryption Procedure
    1. User enters a password (up to 512 characters).
    2. Generate a random salt (16 bytes) for PBKDF2 key derivation.
    3. Derive a 256-bit AES key using PBKDF2-HMAC-SHA256 with the entered password, the salt, and 100,000 iterations.
    4. Generate a random nonce (12 bytes) and encrypt the file using AES-GCM.
    5. Save encryption metadata (salt, nonce, iterations, file extension) in JSON format.

    ### 🔓 Decryption Procedure
    1. User uploads the `.a7` encrypted file.
    2. User enters the password used during encryption.
    3. Extract metadata and ciphertext from the file.
    4. Re-derive the AES key using PBKDF2 with the salt and password.
    5. Use AES-GCM with the key and nonce to decrypt the ciphertext and verify the tag.
    6. If decryption is successful, download the original file with its extension.
    """)

##---

#### 🚀 To Run This App
##
##1. Save the code as `streamlit_app.py`
##2. Run the app in terminal:
##
##```bash
##streamlit run streamlit_app.py
