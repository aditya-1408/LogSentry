import streamlit as st
import pandas as pd
import plotly.express as px
import io
import time

from logsentry.parser import parse_logs, validate_dataframe
from logsentry.detection import detect_suspicious_activity
from logsentry.reporting import generate_alerts_csv, generate_events_csv

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="LogSentry | Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR DARK THEME ---
# Streamlit has a default dark theme if system prefers it, but we can enforce some styling
st.markdown("""
<style>
    /* Add a subtle glow to metric cards */
    div[data-testid="stMetricValue"] {
        color: #00FFCC;
        text-shadow: 0 0 5px rgba(0, 255, 204, 0.5);
    }
    /* Style headers */
    h1, h2, h3 {
        color: #FFFFFF;
        font-family: 'Courier New', Courier, monospace;
    }
    .severity-high { color: #FF4B4B; font-weight: bold; }
    .severity-medium { color: #FFA500; font-weight: bold; }
    .severity-low { color: #00FFCC; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZE SESSION STATE ---
if 'df' not in st.session_state:
    st.session_state.df = None
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'analysis_run' not in st.session_state:
    st.session_state.analysis_run = False

# --- SIDEBAR: UPLOAD & SETTINGS ---
st.sidebar.title("🛡️ LogSentry")
st.sidebar.markdown("Windows Security Log Analyzer")

st.sidebar.header("1. Upload Data")
uploaded_file = st.sidebar.file_uploader("Upload Security Log (CSV)", type=['csv'])

# Settings
st.sidebar.header("2. Detection Settings")
with st.sidebar.expander("Configure Rules", expanded=False):
    failed_threshold = st.number_input("Failed Login Threshold", min_value=2, max_value=50, value=5, step=1)
    time_window_minutes = st.number_input("Rolling Time Window (mins)", min_value=1, max_value=60, value=2, step=1)
    
    st.markdown("---")
    enable_account_detection = st.checkbox("Enable Account-Based Detection (Rule B)", value=True, 
                                           help="Detects failures against an account from multiple IPs.")
    
    st.markdown("---")
    enable_correlation = st.checkbox("Enable Correlation (Rule C)", value=True,
                                     help="Detect successful logons following repeated failures.")
    correlation_window_minutes = st.number_input("Correlation Window (mins)", min_value=1, max_value=60, value=10, step=1)

# Analyze Button
if st.sidebar.button("Run Analysis", type="primary"):
    if uploaded_file is None:
        st.sidebar.error("Please upload a CSV file first.")
    else:
        with st.spinner("Parsing logs..."):
            try:
                # Need to read as file obj, Streamlit uploaded_file is file-like
                uploaded_file.seek(0)
                df = parse_logs(uploaded_file)
                is_valid, msg = validate_dataframe(df)
                if not is_valid:
                    st.sidebar.error(f"Validation failed: {msg}")
                else:
                    st.session_state.df = df
                    st.session_state.analysis_run = False
            except Exception as e:
                st.sidebar.error(f"Error parsing file: {e}")

        if st.session_state.df is not None:
            with st.spinner("Analyzing for suspicious activity..."):
                alerts = detect_suspicious_activity(
                    st.session_state.df,
                    failed_threshold=failed_threshold,
                    time_window_minutes=time_window_minutes,
                    enable_account_detection=enable_account_detection,
                    enable_correlation=enable_correlation,
                    correlation_window_minutes=correlation_window_minutes
                )
                st.session_state.alerts = alerts
                st.session_state.analysis_run = True
                st.sidebar.success(f"Analysis complete! Loaded {len(st.session_state.df)} records.")

# --- MAIN DASHBOARD ---
st.title("LogSentry Dashboard")

if not st.session_state.analysis_run or st.session_state.df is None:
    st.info("Upload a Windows security log CSV file and click 'Run Analysis' to begin.")
    
    with st.expander("Example Normalized CSV Format"):
        st.code("""timestamp,event_id,account,source_ip,computer,description
2023-10-27T08:00:00,4624,jdoe,192.168.1.50,WORKSTATION-01,Successful logon
2023-10-27T08:10:00,4625,admin,192.0.2.10,SRV-01,Failed logon (bad password)""")
        st.markdown("Use the included `data/sample_security_logs.csv` to test the application.")
    st.stop()

df = st.session_state.df
alerts = st.session_state.alerts

# Create Tabs
tab_overview, tab_explorer, tab_alerts, tab_reports = st.tabs([
    "📊 Overview", 
    "🔍 Log Explorer", 
    "🚨 Security Alerts", 
    "📄 Reports"
])

# --- TAB 1: OVERVIEW ---
with tab_overview:
    st.header("Executive Summary")
    
    # Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total_events = len(df)
    success_logons = len(df[df['event_id'] == 4624])
    failed_logons = len(df[df['event_id'] == 4625])
    total_alerts = len(alerts)
    distinct_ips = df[df['source_ip'] != ""]['source_ip'].nunique()
    
    col1.metric("Total Events", f"{total_events:,}")
    col2.metric("Successful Logons", f"{success_logons:,}")
    col3.metric("Failed Logons", f"{failed_logons:,}", delta_color="inverse")
    col4.metric("Suspicious Alerts", f"{total_alerts:,}", delta_color="inverse")
    col5.metric("Distinct Source IPs", f"{distinct_ips:,}")
    
    st.markdown("---")
    
    # Charts
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.subheader("Authentication Status")
        # Bar chart for Success vs Failed
        auth_counts = pd.DataFrame({
            'Status': ['Successful (4624)', 'Failed (4625)'],
            'Count': [success_logons, failed_logons]
        })
        fig_auth = px.bar(auth_counts, x='Status', y='Count', 
                          color='Status', 
                          color_discrete_map={'Successful (4624)': '#00FFCC', 'Failed (4625)': '#FF4B4B'},
                          template="plotly_dark")
        st.plotly_chart(fig_auth, use_container_width=True)
        
    with chart_col2:
        st.subheader("Event Activity Over Time")
        # Group by 1 minute intervals
        if not df.empty:
            time_df = df.copy()
            time_df['minute'] = time_df['timestamp'].dt.floor('min')
            activity = time_df.groupby(['minute', 'event_id']).size().reset_index(name='count')
            activity['event_id'] = activity['event_id'].astype(str)
            fig_time = px.line(activity, x='minute', y='count', color='event_id',
                               labels={'minute': 'Time', 'count': 'Events', 'event_id': 'Event ID'},
                               template="plotly_dark")
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No data available for time series.")
            
    # Additional Charts
    chart_col3, chart_col4 = st.columns(2)
    with chart_col3:
        st.subheader("Top Source IPs (Failed Logons)")
        failed_ips = df[(df['event_id'] == 4625) & (df['source_ip'] != "")].groupby('source_ip').size().reset_index(name='count')
        failed_ips = failed_ips.sort_values(by='count', ascending=False).head(10)
        
        if not failed_ips.empty:
            fig_ips = px.bar(failed_ips, x='source_ip', y='count', template="plotly_dark")
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.info("No valid source IPs found in failed logon events.")
            
    with chart_col4:
        st.subheader("Alerts by Severity")
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            sev_counts = alerts_df.groupby('severity').size().reset_index(name='count')
            fig_sev = px.pie(sev_counts, values='count', names='severity', 
                             color='severity',
                             color_discrete_map={'HIGH': '#FF4B4B', 'MEDIUM': '#FFA500', 'LOW': '#00FFCC'},
                             template="plotly_dark")
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No alerts generated.")

# --- TAB 2: LOG EXPLORER ---
with tab_explorer:
    st.header("Search and Filter Events")
    
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    
    with filter_col1:
        f_event_id = st.multiselect("Event ID", options=sorted(df['event_id'].dropna().unique()))
    with filter_col2:
        valid_accounts = sorted([a for a in df['account'].unique() if a])
        f_account = st.multiselect("Account", options=valid_accounts)
    with filter_col3:
        valid_ips = sorted([ip for ip in df['source_ip'].unique() if ip])
        f_ip = st.multiselect("Source IP", options=valid_ips)
    with filter_col4:
        # Time range slider
        min_time = df['timestamp'].min().to_pydatetime()
        max_time = df['timestamp'].max().to_pydatetime()
        # Fallback if min/max are equal
        if min_time == max_time:
            max_time = min_time + pd.Timedelta(seconds=1).to_pydatetime()
            
        time_range = st.slider("Time Range", min_value=min_time, max_value=max_time, value=(min_time, max_time), format="YYYY-MM-DD HH:mm:ss")
        
    # Apply filters
    filtered_df = df.copy()
    if f_event_id:
        filtered_df = filtered_df[filtered_df['event_id'].isin(f_event_id)]
    if f_account:
        filtered_df = filtered_df[filtered_df['account'].isin(f_account)]
    if f_ip:
        filtered_df = filtered_df[filtered_df['source_ip'].isin(f_ip)]
        
    filtered_df = filtered_df[(filtered_df['timestamp'] >= time_range[0]) & (filtered_df['timestamp'] <= time_range[1])]
    
    st.dataframe(
        filtered_df,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
        },
        use_container_width=True,
        hide_index=True
    )
    st.caption(f"Showing {len(filtered_df)} of {len(df)} events.")

# --- TAB 3: SECURITY ALERTS ---
with tab_alerts:
    st.header("Detected Security Incidents")
    
    if not alerts:
        st.success("No suspicious activity detected based on current rules.")
    else:
        alerts_df = pd.DataFrame(alerts)
        
        # Alerts filter
        a_col1, a_col2, a_col3 = st.columns(3)
        with a_col1:
            a_severity = st.multiselect("Severity", options=alerts_df['severity'].unique(), default=alerts_df['severity'].unique().tolist())
        with a_col2:
            a_rule = st.multiselect("Rule Name", options=alerts_df['rule_name'].unique())
        with a_col3:
            # We must handle comma-separated IPs in alerts for filtering
            all_alert_ips = set()
            for ip_str in alerts_df['source_ip']:
                for ip in ip_str.split(", "):
                    if ip and ip != "Unknown":
                        all_alert_ips.add(ip)
            a_ip = st.multiselect("Source IP", options=sorted(list(all_alert_ips)))
            
        filtered_alerts = alerts_df.copy()
        if a_severity:
            filtered_alerts = filtered_alerts[filtered_alerts['severity'].isin(a_severity)]
        if a_rule:
            filtered_alerts = filtered_alerts[filtered_alerts['rule_name'].isin(a_rule)]
        if a_ip:
            # Check if any selected IP is in the alert's source_ip string
            mask = filtered_alerts['source_ip'].apply(lambda x: any(ip in x for ip in a_ip))
            filtered_alerts = filtered_alerts[mask]
            
        if filtered_alerts.empty:
            st.info("No alerts match the selected filters.")
        else:
            for index, alert in filtered_alerts.iterrows():
                # Color code based on severity
                sev_color = "red" if alert['severity'] == "HIGH" else "orange" if alert['severity'] == "MEDIUM" else "green"
                
                with st.expander(f"[{alert['severity']}] {alert['rule_name']} - {alert['source_ip']}"):
                    st.markdown(f"**Severity:** <span style='color:{sev_color}'>{alert['severity']}</span>", unsafe_allow_html=True)
                    st.markdown(f"**Rule:** {alert['rule_name']}")
                    st.markdown(f"**Source IP(s):** {alert['source_ip']}")
                    st.markdown(f"**Account(s):** {alert['account']}")
                    st.markdown(f"**Time Window:** {alert['first_timestamp']} to {alert['last_timestamp']}")
                    st.markdown(f"**Events Involved:** {alert['event_count']}")
                    st.markdown(f"**Explanation:** {alert['reason']}")
                    
                    st.info(f"**Recommended Action:** {alert['recommendation']}")
                    
                    # Note: We could query the DataFrame here to show supporting events,
                    # but for simplicity and performance we'll direct the user to the Log Explorer.
                    st.caption(f"Use the Log Explorer to view events for {alert['source_ip']} during this time window.")

# --- TAB 4: REPORTS ---
with tab_reports:
    st.header("Generate & Download Reports")
    st.markdown("Export the analyzed logs and detected incidents for your records or further investigation.")
    
    st.warning("Note: User-controlled fields in CSV exports are sanitized to prevent spreadsheet formula execution (CSV Injection).")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Security Alerts Report")
        st.markdown(f"Contains {len(alerts)} detected incidents.")
        
        alerts_csv = generate_alerts_csv(alerts)
        st.download_button(
            label="Download Alerts CSV",
            data=alerts_csv,
            file_name="logsentry_alerts_report.csv",
            mime="text/csv",
            type="primary"
        )
        
    with col2:
        st.subheader("Filtered Events Export")
        st.markdown(f"Exports the {len(filtered_df)} events currently visible in the Log Explorer tab.")
        
        events_csv = generate_events_csv(filtered_df)
        st.download_button(
            label="Download Events CSV",
            data=events_csv,
            file_name="logsentry_filtered_events.csv",
            mime="text/csv"
        )
