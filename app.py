import streamlit as st
from detector import analyze_url, analyze_email

st.set_page_config(page_title="Anti-Phishing Bot", page_icon="🛡️", layout="wide")
st.title("🛡️ Anti-Phishing Bot")
st.caption("Mistral-7B-Instruct + LangChain + vector embeddings for defensive threat detection")

with st.sidebar:
    st.header("Pipeline")
    st.markdown("1. URL/email feature extraction\n2. Security-knowledge vector retrieval\n3. LangChain + Mistral analysis\n4. Explainable risk scoring")
    st.info("The demo works without an API key. Add MISTRAL_API_KEY for model-backed analysis.")

def show(result):
    score = result["risk_score"]
    if score >= 70: st.error(f"🚨 {result['verdict']} — Risk {score}/100")
    elif score >= 40: st.warning(f"⚠️ {result['verdict']} — Risk {score}/100")
    else: st.success(f"✅ {result['verdict']} — Risk {score}/100")
    a,b = st.columns(2)
    with a:
        st.subheader("Detected signals")
        for x in result["signals"]: st.write("• " + x)
    with b:
        st.subheader("Recommended action")
        st.write(result["recommendation"])
    st.subheader("Analysis")
    st.write(result["explanation"])
    with st.expander("Technical context"):
        st.json({"model": result["model"], "mode": result["mode"], "retrieved_context": result["retrieved_context"]})

url_tab, email_tab = st.tabs(["🔗 URL Scanner", "✉️ Email Scanner"])
with url_tab:
    url = st.text_input("URL", placeholder="https://example.com/login")
    if st.button("Analyze URL", type="primary"):
        if url.strip():
            with st.spinner("Analyzing URL..."): show(analyze_url(url.strip()))
        else: st.warning("Enter a URL first.")
with email_tab:
    subject = st.text_input("Subject", placeholder="Urgent: Verify your account")
    body = st.text_area("Email body", height=220)
    if st.button("Analyze Email", type="primary"):
        if subject.strip() or body.strip():
            with st.spinner("Analyzing email..."): show(analyze_email(subject.strip(), body.strip()))
        else: st.warning("Paste an email first.")

st.divider()
st.caption("Defensive use only. Never enter real passwords, OTPs, card data, or API keys.")
