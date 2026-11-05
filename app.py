"""Local interactive scanner. Never deploy this entrypoint publicly."""
import os
import streamlit as st
from vulnscope.scanner import run_scan
from vulnscope.demos import available_demos, load_demo
from vulnscope.ui import render_results

st.set_page_config(page_title="VulnScope | Local Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ VulnScope")
st.caption("Scope-Limited Network Security Assessment · Local Edition")
st.warning("Only assess systems you own or have explicit written authorization to test. Localhost-only by default. Public deployment must use public_app.py.")

if os.getenv("VULNSCOPE_PUBLIC_DEMO", "").strip() == "1":
    st.error("Local scanner disabled: VULNSCOPE_PUBLIC_DEMO=1. Run public_app.py instead.")
    st.stop()

local_tab, demo_tab = st.tabs(["Run authorized local scan", "Recorded demonstrations"])
with local_tab:
    with st.form("scan"):
        target = st.text_input("Authorized target IP", value="127.0.0.1", help="IP literals or localhost only; additional private IPs must be exact-allowlisted by machine owner.")
        ports = st.text_input("TCP ports (comma list or range, max 32)", value="80,443,8765,8766,8767,8768")
        c1, c2 = st.columns(2)
        timeout = c1.slider("Connection timeout (seconds)", 0.2, 2.0, 0.75, 0.05)
        workers = c2.slider("Concurrent workers", 1, 8, 6)
        authorized = st.checkbox("I own this target or have explicit permission to assess it.")
        submit = st.form_submit_button("Start authorized scan", type="primary")
    if submit:
        try:
            with st.spinner("Performing bounded, read-only checks..."):
                st.session_state["last_local_scan"] = run_scan(target, ports, authorized, timeout, workers)
        except (PermissionError, ValueError) as exc:
            st.error(str(exc))
        except Exception as exc:
            st.error(f"Scan encountered an unexpected error: {type(exc).__name__}")
    if "last_local_scan" in st.session_state:
        render_results(st.session_state["last_local_scan"], "local")
with demo_tab:
    demos = available_demos()
    if demos:
        selected = st.selectbox("Historical lab capture", demos, format_func=lambda path: path.stem.replace("lab-", "").replace("-", " ").title())
        render_results(load_demo(selected), "local-demo")
    else:
        st.info("No recorded fixtures yet. Run python record_demos.py after starting demo_lab.py.")
