"""Shared Streamlit result views for live local and historical public demos."""
import pandas as pd
import streamlit as st
from .findings import SEVERITIES, RUBRIC
from .reporting import json_report, csv_report, html_report


def render_results(scan: dict, prefix: str = "scan") -> None:
    historical = scan.get("kind") == "recorded-local-lab-scan"
    st.info("RECORDED HISTORICAL LAB RESULT — not a live scan." if historical else "LIVE LOCAL SCAN — results from this session.")
    if scan.get("scan_incomplete"):
        st.warning("Assessment reached its runtime budget; some service checks were skipped.")
    st.caption(f"Target {scan['target']} · UTC {scan['started_at_utc']} · {scan['duration_seconds']} s · {scan.get('source_note','')}")
    open_ports = sum(p["state"] == "open" for p in scan.get("ports", []))
    metrics = st.columns(4)
    metrics[0].metric("Ports scanned", len(scan.get("ports", [])))
    metrics[1].metric("Open TCP ports", open_ports)
    metrics[2].metric("Findings", len(scan.get("findings", [])))
    metrics[3].metric("Medium +", sum(scan["severity_counts"].get(key, 0) for key in ("Critical", "High", "Medium")))
    st.subheader("Severity distribution")
    chart_df = pd.DataFrame([{"Severity": s, "Count": scan["severity_counts"].get(s, 0)} for s in SEVERITIES]).set_index("Severity")
    st.bar_chart(chart_df, horizontal=True)
    left, right = st.tabs(["Network & protocols", "Security findings"])
    with left:
        st.markdown("**TCP connectivity**")
        st.dataframe(scan.get("ports", []), use_container_width=True, hide_index=True)
        st.markdown("**Service associations and observed banners**")
        st.dataframe(scan.get("services", []), use_container_width=True, hide_index=True)
        with st.expander("HTTP and TLS evidence"):
            st.json({"http": scan.get("http", []), "tls": scan.get("tls", [])})
    with right:
        chosen = st.multiselect("Severity filter", SEVERITIES, default=list(SEVERITIES), key=f"{prefix}-severity")
        subset = [f for f in scan.get("findings", []) if f["severity"] in chosen]
        st.dataframe([{"Severity": f["severity"], "Finding": f["title"], "Port": f["port"], "ID": f["id"]} for f in subset],
                     use_container_width=True, hide_index=True)
        for i, f in enumerate(subset):
            with st.expander(f"{f['severity']} · {f['title']} · TCP/{f['port']}"):
                st.write("**Evidence:**", f["evidence"])
                st.write("**Impact:**", f["impact"])
                st.write("**Remediation:**", f["remediation"])
                st.write("**Verification limitations:**", f["limitations"])
                st.markdown(f"Reference: [{f['reference']}]({f['reference']})")
    with st.expander("Methodology, severity rubric and limitations"):
        st.write(scan["methodology"])
        st.write(scan["limitations"])
        for severity, description in RUBRIC.items():
            st.write(f"**{severity}:** {description}")
    st.subheader("Download assessment")
    d1, d2, d3 = st.columns(3)
    d1.download_button("Download JSON", json_report(scan), file_name="vulnscope-assessment.json", mime="application/json", key=f"{prefix}-json")
    d2.download_button("Download CSV", csv_report(scan), file_name="vulnscope-findings.csv", mime="text/csv", key=f"{prefix}-csv")
    d3.download_button("Download HTML", html_report(scan), file_name="vulnscope-report.html", mime="text/html", key=f"{prefix}-html")
