import base64
import hashlib
import time
from urllib.parse import quote

import jwt  # PyJWT
import requests
import streamlit as st
import streamlit.components.v1 as components
from cryptography.hazmat.primitives import serialization

st.set_page_config(page_title="Studio Replen (test)", layout="wide")
cfg = st.secrets["snowflake"]


def keypair_jwt() -> str:
    """Builds the short-lived signed token Snowflake uses to recognise the service user."""
    key = serialization.load_pem_private_key(cfg["private_key"].encode(), password=None)
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    fingerprint = base64.b64encode(hashlib.sha256(pub_der).digest()).decode()
    qualified = f'{cfg["account"].upper().replace(".", "-")}.{cfg["user"].upper()}'
    now = int(time.time())
    payload = {"iss": f"{qualified}.SHA256:{fingerprint}", "sub": qualified, "iat": now, "exp": now + 3000}
    return jwt.encode(payload, cfg["private_key"], algorithm="RS256")


def mint_embed_url() -> str:
    """Asks Snowflake for a single-use embed URL of the app."""
    db, schema, app = (quote(p) for p in cfg["app"].split("."))
    url = f'{cfg["account_url"]}/api/v2/databases/{db}/schemas/{schema}/streamlits/{app}:generate-embed-url'
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {keypair_jwt()}",
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "X-Snowflake-Role": cfg["role"],
            "Content-Type": "application/json",
        },
        json={"parent_origin": cfg["parent_origin"]},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"{resp.status_code}: {resp.text}")
    return resp.json()["embed_url"]


if st.button("↻ Riavvia l'app"):  # the URL is single-use: a restart needs a new one
    st.session_state.pop("embed_url", None)

if "embed_url" not in st.session_state:
    try:
        st.session_state["embed_url"] = mint_embed_url()
    except Exception as e:
        st.error(f"Impossibile aprire l'app: {e}")
        st.stop()

components.iframe(st.session_state["embed_url"], height=950, scrolling=True)