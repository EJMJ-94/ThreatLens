import streamlit as st
import pandas as pd

# ThreatLens: AI-Assisted Security Signal Interpretation
st.set_page_config(page_title="ThreatLens", page_icon="🛡️")
st.title("🛡️ ThreatLens AI")
st.caption("AI Security Automation for Defensive Operations")

# --- WEEK 1: Parse and normalize data ---
def load_data(file):
    df = pd.read_csv(file)
    df['timestamp'] = pd.to_datetime(df['timestamp']) 
    return df

# --- WEEK 2: Detection logic ---
def detect_anomalies(df):
    anomalies = []
    # Identify brute force (5+ failures from one IP)
    fail_counts = df[df['event_type'] == 'login_fail']['source_ip'].value_counts()
    for ip, count in fail_counts.items():
        if count >= 5:
            anomalies.append(f"UNUSUAL: IP {ip} had {count} failed logins.")
    return anomalies

# --- WEEK 3: AI Interpretation with Ethical Guardrails ---
def ai_summary(issues):
    if not issues:
        return "System behavior appears normal based on baselines."
    
    summary = "### 🤖 AI Security Brief\n"
    summary += f"The analysis identified {len(issues)} signals of concern. These patterns may indicate unauthorized access attempts.\n\n"
    summary += "**Ethical Guardrails:** This is for decision support only. It does not prove malicious intent or assign blame."
    return summary

# --- WEEK 4: User Interface ---
uploaded_file = st.sidebar.file_uploader("Upload security_logs.csv", type="csv")
if uploaded_file:
    data = load_data(uploaded_file)
    st.write("### Raw Security Logs", data)
    findings = detect_anomalies(data)
    st.markdown("---")
    st.subheader("Analysis Results")
    st.write(ai_summary(findings))
else:
    st.info("Please upload your 'security_logs.csv' file from the sidebar.")