from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import streamlit as st

from scanner import scan_site

st.set_page_config(page_title="WebGuard AI", page_icon="🛡️", layout="wide")
st.title("🛡️ WebGuard AI")
st.caption("A beginner-friendly website security checker for sites you own or are authorized to test.")

with st.sidebar:
    st.header("Safety first")
    st.warning(
        "Only scan websites you own or have explicit permission to test. "
        "This starter version performs limited, non-destructive checks only."
    )
    st.write("• Low request volume")
    st.write("• Same-host crawling")
    st.write("• No login bypass, data extraction, destructive payloads, or denial-of-service tests")

url = st.text_input("Website URL", placeholder="https://example.com")
authorized = st.checkbox("I own this website or have explicit permission to assess it.")
run = st.button("Run safe checks", type="primary", disabled=not authorized)

if run:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        st.error("Enter a valid http:// or https:// URL.")
        st.stop()

    with st.spinner("Checking the site with low-impact requests..."):
        try:
            results = scan_site(url.strip())
        except Exception as exc:
            st.error(f"Scan could not complete: {exc}")
            st.stop()

    st.session_state["results"] = results
    st.session_state["scan_url"] = url.strip()

if "results" in st.session_state:
    results = st.session_state["results"]
    st.subheader("Results")
    st.write(f"Target: `{st.session_state['scan_url']}`")
    st.caption("These checks identify possible issues; they do not prove the site is secure or vulnerable.")

    summary = results["summary"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Pages checked", summary["pages_checked"])
    c2.metric("Findings", summary["findings"])
    c3.metric("Scan time (UTC)", results["timestamp_utc"])

    if results["findings"]:
        for finding in results["findings"]:
            with st.expander(f"{finding['severity']} — {finding['title']}", expanded=True):
                st.write(finding["description"])
                st.write("**Evidence:** " + finding["evidence"])
                st.write("**Suggested fixes:**")
                for fix in finding["suggestions"]:
                    st.write(f"- {fix}")
                st.caption(f"Confidence: {finding['confidence']}. Category: {finding['category']}.")
    else:
        st.success("No issues were detected by these limited checks. This is not a guarantee of security.")

    report_json = json.dumps(results, indent=2)
    st.download_button(
        "Download JSON report",
        data=report_json,
        file_name="webguard-report.json",
        mime="application/json",
    )
    st.download_button(
        "Download HTML report",
        data=results["html_report"],
        file_name="webguard-report.html",
        mime="text/html",
    )

st.divider()
st.caption("WebGuard AI starter project • Keep testing authorized, scoped, and non-destructive.")
