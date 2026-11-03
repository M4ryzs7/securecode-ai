"""app.py - SecureCode AI Streamlit dashboard. Run with: streamlit run app.py"""

import os
import re
import tempfile
from pathlib import Path

import streamlit as st

from analyzer import analyze_vulnerabilities
from ollama_client import MODEL_NAME, check_ollama
from report import build_json_report, build_markdown_report
from safe_zip import MAX_ZIP_BYTES
from scanner import scan_upload

MAX_UPLOAD_BYTES = MAX_ZIP_BYTES
SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

st.set_page_config(page_title="SecureCode AI", page_icon="🛡️", layout="wide")


def clean(text, limit=160) -> str:
    """Make untrusted text (file names, Bandit text) safe to use in labels."""
    return re.sub(r"[`*<>\[\]~]", "", str(text))[:limit]


@st.cache_data(ttl=10)
def ollama_status() -> dict:
    return check_ollama()


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.header("⚙️ Settings")

    status = ollama_status()
    if status["available"] and status["model_installed"]:
        st.success(f"Local AI ready ({MODEL_NAME})")
    else:
        st.warning(status["message"])
    if st.button("Re-check Ollama"):
        ollama_status.clear()
        st.rerun()

    use_ai = st.checkbox("Add AI explanations", value=True,
                         help="Uses your local Ollama model. Curated guidance is always shown.")
    max_ai = st.slider("Max findings to explain with AI", 1, 25, 10,
                       help="A small local model takes several seconds per finding.")

    st.divider()
    st.caption(
        "Limits: 10 MB upload, 200 Python files per ZIP, 1 MB per file. "
        "Uploaded code is analyzed, never executed."
    )

# --------------------------------------------------------------------- main
st.title("🛡️ SecureCode AI")
st.write("Static analysis (Bandit) + curated remediation guidance + local AI explanations.")

uploaded = st.file_uploader("Upload a Python file or a ZIP of a Python project", type=["py", "zip"])

if uploaded is not None:
    st.success(f"Selected: {clean(uploaded.name)} ({uploaded.size / 1024:.1f} KB)")

    if st.button("🔍 Scan", type="primary"):
        if uploaded.size > MAX_UPLOAD_BYTES:
            st.error("File is larger than 10 MB.")
        else:
            temp_path = None
            try:
                suffix = Path(uploaded.name).suffix.lower()
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded.getvalue())
                    temp_path = tmp.name
                with st.spinner("Scanning with Bandit..."):
                    result = scan_upload(temp_path, uploaded.name)
            finally:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)

            st.session_state["scan_result"] = result
            st.session_state.pop("ai_result", None)


def render_finding(finding: dict, item: dict | None):
    icon = SEVERITY_ICON.get(finding["severity"], "⚪")
    label = (f"{icon} {clean(finding['id'])} · {clean(finding['test_id'])} · "
             f"{clean(finding['type'])} · {clean(finding['severity'])} · "
             f"{clean(finding['file'])}:{finding['line']}")

    with st.expander(label):
        st.markdown("#### Bandit result")
        st.text(f"Severity: {finding['severity']}   Confidence: {finding['confidence']}"
                + (f"   {finding['cwe']}" if finding.get("cwe") else ""))
        st.text(finding["description"])
        st.code(finding["code"], language="python")
        if str(finding.get("more_info", "")).startswith("https://"):
            st.markdown(f"[Bandit documentation]({finding['more_info']})")

        if item is None:
            return

        st.markdown("#### Guidance")
        st.markdown(f"**{item['category_label']}**")
        if not item["curated"]:
            st.caption("No curated rule exists for this test ID; showing Bandit's own text only.")
        st.markdown(f"**What it means:** {item['explanation']}")
        st.markdown(f"**Potential impact:** {item['impact']}")
        st.markdown(f"**Recommendation:** {item['recommendation']}")
        for note in item["notes"]:
            st.info(note)
        if item["fixed_code"]:
            st.caption("Illustrative example. Adapt and test it. It is never applied to your files.")
            st.code(item["fixed_code"], language="python")

        if item["ai_status"] == "ok":
            st.markdown(f"#### 🤖 AI explanation ({MODEL_NAME}, unverified)")
            st.text(item["ai_explanation"])  # st.text: AI output is never rendered as markdown/HTML
        elif item["ai_note"]:
            st.caption(f"🤖 {item['ai_note']}")


if "scan_result" in st.session_state:
    result = st.session_state["scan_result"]
    st.divider()

    if result["status"] != "success":
        st.error(result["error"])
    else:
        findings = result["vulnerabilities"]
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ICON}

        st.subheader(f"Scan results: {clean(result['file'])}")
        for warning in result.get("warnings", []):
            st.warning(warning)

        cols = st.columns(5)
        cols[0].metric("Files scanned", result["files_scanned"])
        cols[1].metric("Findings", result["total_issues"])
        cols[2].metric("🔴 High", counts["HIGH"])
        cols[3].metric("🟠 Medium", counts["MEDIUM"])
        cols[4].metric("🟡 Low", counts["LOW"])

        if result.get("skipped_files"):
            with st.expander(f"Skipped files ({len(result['skipped_files'])})"):
                for entry in result["skipped_files"][:100]:
                    st.text(f"{entry['name']}: {entry['reason']}")
        if result.get("scan_errors"):
            with st.expander(f"⚠️ Files Bandit could not analyze ({len(result['scan_errors'])})"):
                for entry in result["scan_errors"]:
                    st.text(f"{entry['file']}: {entry['reason']}")

        if not findings:
            st.success("No Bandit findings. This does not prove the code is secure: "
                       "Bandit only detects known risky patterns.")
        else:
            if st.button("🤖 Get guidance and AI explanations"):
                bar = st.progress(0.0, text="Preparing guidance...")

                def on_progress(done, total, finding):
                    bar.progress(done / total if total else 1.0,
                                 text=f"Asking the local model... ({done}/{total})")

                st.session_state["ai_result"] = analyze_vulnerabilities(
                    result, use_ai=use_ai, max_ai_findings=max_ai, progress_callback=on_progress
                )
                bar.empty()

            ai_result = st.session_state.get("ai_result")
            by_id = {}
            if ai_result:
                if ai_result.get("status") == "success":
                    by_id = {a["id"]: a for a in ai_result["analyses"]}
                    st.info(ai_result["summary"])
                    for warning in ai_result.get("warnings", []):
                        st.warning(warning)
                else:
                    st.error(ai_result.get("error", "Analysis failed."))

            chosen = st.multiselect("Show severities", list(SEVERITY_ICON),
                                    default=list(SEVERITY_ICON))
            for finding in findings:
                if finding["severity"] in chosen or finding["severity"] not in SEVERITY_ICON:
                    render_finding(finding, by_id.get(finding["id"]))

            st.divider()
            st.subheader("📄 Download report")
            d1, d2 = st.columns(2)
            d1.download_button("Markdown report",
                               build_markdown_report(result, ai_result),
                               file_name="securecode_report.md", mime="text/markdown")
            d2.download_button("JSON report",
                               build_json_report(result, ai_result),
                               file_name="securecode_report.json", mime="application/json")

        st.warning(
            "Bandit flags risky code patterns; it cannot tell whether data is attacker-controlled. "
            "Curated guidance is hand-written; AI text comes from a small local model and is unverified. "
            "Review and test any change yourself. Nothing is applied to your code automatically."
        )
