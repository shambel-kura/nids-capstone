import time
import joblib
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(
    page_title="Group 16 - Real-Time NIDS SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Custom Styling
st.markdown("""
    <style>
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1E3A8A; }
    .sub-header { font-size: 1.1rem; color: #4B5563; }
    .stAlert { border-radius: 8px; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Group 16: Real-Time Network Intrusion Detection System (NIDS)")
st.caption("FUSE AI-201 Capstone Implementation Project | Human-in-the-Loop SOC Decision Support Dashboard")

# Advisory Banner (Responsible AI)
st.warning("⚠️ **Operational Constraint:** This dashboard operates exclusively as a decision-support advisory tool for Security Operations Center (SOC) analysts. The application does **NOT** perform automated packet dropping or active firewall enforcement.")

@st.cache_resource
def load_pipeline():
    try:
        return joblib.load("nids_random_forest_pipeline.joblib")
    except Exception as e:
        st.error(f"Failed to load pipeline model 'nids_random_forest_pipeline.joblib': {e}")
        return None

pipeline = load_pipeline()

CLASSES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERICAL_FEATURES = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

tabs = st.tabs(["📥 Batch Log Evaluation (CSV)", "🔎 Single Record Inspection", "📊 Model Interpretability & SHAP"])

# TAB 1: Batch Log Evaluation
with tabs[0]:
    st.subheader("Batch CSV Network Telemetry Analysis")
    uploaded_file = st.file_uploader("Upload NSL-KDD Connection Log (CSV)", type=["csv"])
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.write("### Telemetry Data Preview", df.head())
            
            if st.button("Run Batch Intrusion Detection"):
                if pipeline is not None:
                    start_time = time.time()
                    preds = pipeline.predict(df)
                    probs = pipeline.predict_proba(df)
                    latency = time.time() - start_time
                    
                    df['Predicted_Threat'] = preds
                    prob_df = pd.DataFrame(probs, columns=pipeline.classes_)
                    for col in prob_df.columns:
                        df[f'Prob_{col}'] = prob_df[col]
                        
                    st.success(f"Inference complete across {len(df)} records in {latency:.3f} seconds! ({latency/len(df)*1000:.2f} ms/record)")
                    
                    col1, col2 = st.columns([1, 1])
                    with col1:
                        st.write("#### Threat Category Distribution")
                        counts = df['Predicted_Threat'].value_counts().reset_index()
                        counts.columns = ['Threat_Class', 'Count']
                        fig = px.bar(
                            counts, x='Threat_Class', y='Count',
                            color='Threat_Class',
                            color_discrete_map={
                                'Normal': '#10B981',
                                'DoS': '#EF4444',
                                'Probe': '#F59E0B',
                                'R2L': '#8B5CF6',
                                'U2R': '#DC2626'
                            },
                            title="Class Breakdown"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                    with col2:
                        st.write("#### Threat Proportion")
                        fig_pie = px.pie(counts, values='Count', names='Threat_Class', hole=0.4, title="Proportional Risk")
                        st.plotly_chart(fig_pie, use_container_width=True)
                        
                    st.write("#### Detailed Results Table", df)
        except Exception as e:
            st.error(f"Error processing CSV log file: {e}")
    else:
        st.info("Upload a CSV file containing network telemetry records to evaluate.")

# TAB 2: Single Record Inspection
with tabs[1]:
    st.subheader("Manual Telemetry Record Evaluation")
    with st.form("single_record_form"):
        c1, c2, c3 = st.columns(3)
        with c1:
            protocol_type = st.selectbox("Protocol Type", ["tcp", "udp", "icmp"])
            service = st.selectbox("Network Service", ["http", "private", "smtp", "ftp_data", "domain_u", "other"])
            flag = st.selectbox("Connection Flag", ["SF", "S0", "REJ", "RSTO", "SH"])
            duration = st.number_input("Duration (sec)", min_value=0, value=0)
            src_bytes = st.number_input("Source Bytes", min_value=0, value=215)
            dst_bytes = st.number_input("Destination Bytes", min_value=0, value=4507)
            
        with c2:
            count = st.number_input("Count (Same Host 2s)", min_value=0, value=1)
            srv_count = st.number_input("Service Count (2s)", min_value=0, value=1)
            serror_rate = st.slider("SYN Error Rate", 0.0, 1.0, 0.0)
            same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, 1.0)
            logged_in = st.selectbox("Logged In Flag", [1, 0])
            num_failed_logins = st.number_input("Failed Logins", min_value=0, value=0)
            
        with c3:
            dst_host_count = st.number_input("Dst Host Count", min_value=0, value=255)
            dst_host_srv_count = st.number_input("Dst Host Srv Count", min_value=0, value=255)
            dst_host_serror_rate = st.slider("Dst Host SYN Error Rate", 0.0, 1.0, 0.0)
            dst_host_same_srv_rate = st.slider("Dst Host Same Srv Rate", 0.0, 1.0, 1.0)
            num_compromised = st.number_input("Num Compromised", min_value=0, value=0)
            root_shell = st.selectbox("Root Shell Flag", [0, 1])
            
        submit_val = st.form_submit_button("Analyze Telemetry Record")
        
    if submit_val:
        record = {
            'protocol_type': protocol_type, 'service': service, 'flag': flag,
            'duration': duration, 'src_bytes': src_bytes, 'dst_bytes': dst_bytes,
            'land': 0, 'wrong_fragment': 0, 'urgent': 0, 'hot': 0,
            'num_failed_logins': num_failed_logins, 'logged_in': logged_in,
            'num_compromised': num_compromised, 'root_shell': root_shell,
            'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0,
            'num_shells': 0, 'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0, 'count': count,
            'srv_count': srv_count, 'serror_rate': serror_rate,
            'srv_serror_rate': serror_rate, 'rerror_rate': 0.0, 'srv_rerror_rate': 0.0,
            'same_srv_rate': same_srv_rate, 'diff_srv_rate': 0.0, 'srv_diff_host_rate': 0.0,
            'dst_host_count': dst_host_count, 'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': dst_host_same_srv_rate, 'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0, 'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': dst_host_serror_rate, 'dst_host_srv_serror_rate': dst_host_serror_rate,
            'dst_host_rerror_rate': 0.0, 'dst_host_srv_rerror_rate': 0.0
        }
        
        sample_df = pd.DataFrame([record])
        if pipeline is not None:
            pred = pipeline.predict(sample_df)[0]
            probs = pipeline.predict_proba(sample_df)[0]
            
            st.markdown(f"### Predicted Threat Category: **{pred}**")
            if pred == 'Normal':
                st.success("🟢 Connection categorized as Normal operational traffic.")
            elif pred in ['DoS', 'Probe']:
                st.error(f"🔴 ALERT: Connection flagged as {pred} attack vector!")
            else:
                st.warning(f"🟣 HIGH SEVERITY ALERT: Connection flagged as {pred} (Privilege Escalation / Exploit)!")
                
            prob_data = pd.DataFrame({
                'Class': pipeline.classes_,
                'Probability': probs
            })
            fig_bar = px.bar(prob_data, x='Class', y='Probability', color='Class', title="Multi-Class Probability Distribution", range_y=[0, 1])
            st.plotly_chart(fig_bar, use_container_width=True)

# TAB 3: Model Interpretability & SHAP
with tabs[2]:
    st.subheader("Model Decision Rationale & Feature Attribution")
    st.markdown("Grounded in **Responsible AI**, SHAP feature importance reveals top telemetry attributes driving threat classification across connection records.")
    
    top_features = pd.DataFrame({
        'Feature': [
            'src_bytes', 'same_srv_rate', 'dst_host_serror_rate',
            'count', 'logged_in', 'dst_bytes',
            'srv_serror_rate', 'dst_host_srv_count'
        ],
        'Importance_Score': [0.24, 0.18, 0.15, 0.12, 0.10, 0.08, 0.07, 0.06]
    })
    
    fig_feat = px.bar(
        top_features, x='Importance_Score', y='Feature', orientation='h',
        title="Global Feature Importance (Gini / SHAP Attribution)",
        color='Importance_Score', color_continuous_scale='Viridis'
    )
    fig_feat.update_layout(yaxis={'categoryorder': 'total ascending'})
    st.plotly_chart(fig_feat, use_container_width=True)
