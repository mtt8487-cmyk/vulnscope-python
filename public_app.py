"""Deployment-safe entrypoint: reads static packaged JSON only; no scanner imports."""
import streamlit as st
from vulnscope.demos import available_demos, load_demo
from vulnscope.ui import render_results

st.set_page_config(page_title="VulnScope | Portfolio Demo", page_icon="🛡️", layout="wide")
st.title("🛡️ VulnScope — Security Assessment Explorer")
st.caption("Portfolio demo · Real recorded local-lab results · No live network scanning")
st.info("This public site never initiates scans. Results below were captured earlier against controlled loopback-only test services.")
paths = available_demos()
if not paths:
    st.error("No valid recorded demonstrations were packaged with this deployment.")
    st.stop()
chosen = st.selectbox("Explore a lab assessment", paths,
    format_func=lambda path: path.stem.replace("lab-", "").replace("-", " ").title())
render_results(load_demo(chosen), "public")
st.caption("Source code includes a separate local-only scanner for authorized environments. A successful assessment is not proof that a system is secure.")
