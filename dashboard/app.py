import sys
from pathlib import Path


from datetime import datetime

from streamlit_autorefresh import st_autorefresh
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import plotly.express as px

from core.investigator import investigate

# --------------------------------------------------
# Page Configuration
# --------------------------------------------------

st.set_page_config(

    page_title="SentinelIR",

    page_icon="🛡️",

    layout="wide"

)

# ---------------------------------------
# Auto Refresh every 5 seconds
# ---------------------------------------

st_autorefresh(

    interval=5000,

    key="sentinel_refresh"

)

# --------------------------------------------------
# Investigation
# --------------------------------------------------

report = investigate()


scan_time = datetime.now().strftime("%H:%M:%S")
# --------------------------------------------------
# Sidebar
# --------------------------------------------------

st.sidebar.title("🛡️ SentinelIR")

st.caption(f"🕒 Last Scan: {scan_time}")
st.sidebar.success("System Status: Monitoring")

st.sidebar.metric(
    "Threat Score",
    report["threat_score"]
)

st.sidebar.metric(
    "Alerts",
    len(report["alerts"])
)

st.sidebar.metric(
    "Incidents",
    len(report["incidents"])
)

# --------------------------------------------------
# IOC Dashboard
# --------------------------------------------------

st.markdown("---")

st.subheader("🔎 Indicators of Compromise")

iocs = report.get("iocs", {})

ioc_col1, ioc_col2 = st.columns(2)

with ioc_col1:

    st.write("### 🌐 IP Addresses")

    ips = iocs.get("ips", [])

    if ips:
        for ip in ips:
            st.code(ip)
    else:
        st.info("No IP addresses detected.")

    st.write("### 🔗 URLs")

    urls = iocs.get("urls", [])

    if urls:
        for url in urls:
            st.code(url)
    else:
        st.info("No URLs detected.")


with ioc_col2:

    st.write("### 📂 Suspicious Paths")

    paths = iocs.get("paths", [])

    if paths:
        for path in paths:
            st.code(path)
    else:
        st.info("No suspicious paths detected.")

    st.write("### 💻 Commands")

    commands = iocs.get("commands", [])

    if commands:
        for command in commands:
            st.code(command)
    else:
        st.info("No suspicious commands detected.")

st.write("### 🔑 Registry Indicators")

registry = iocs.get("registry", [])

if registry:
    for item in registry:
        st.code(item)
else:
    st.info("No registry indicators detected.")

st.sidebar.markdown("---")

st.sidebar.write("### Quick Summary")

high = sum(
    1 for a in report["alerts"]
    if a.get("severity") == "HIGH"
)

medium = sum(
    1 for a in report["alerts"]
    if a.get("severity") == "MEDIUM"
)

low = sum(
    1 for a in report["alerts"]
    if a.get("severity") == "LOW"
)

st.sidebar.write(f"🔴 High : {high}")
st.sidebar.write(f"🟠 Medium : {medium}")
st.sidebar.write(f"🟢 Low : {low}")
# --------------------------------------------------
# Title
# --------------------------------------------------

st.title("🛡️ SentinelIR")

st.caption("Endpoint Detection & Incident Response Dashboard")

st.markdown("---")

# --------------------------------------------------
# Metrics
# --------------------------------------------------

col1, col2, col3, col4, col5 = st.columns(5)

score = report["threat_score"]

if score >= 70:
    color = "🔴"

elif score >= 40:
    color = "🟠"

else:
    color = "🟢"

col1.metric(
    "Threat Score",
    f"{color} {score}"
)

col2.metric(
    "Processes",
    len(report["processes"])
)

col3.metric(
    "Connections",
    len(report["connections"])
)

col4.metric(
    "Alerts",
    len(report["alerts"])
)

col5.metric(
    "Incidents",
    len(report["incidents"])
)

st.progress(report["threat_score"] / 100)


c1, c2, c3 = st.columns(3)

c1.error(f"🔴 High Alerts: {high}")

c2.warning(f"🟠 Medium Alerts: {medium}")

c3.success(f"🟢 Low Alerts: {low}")
st.markdown("---")



# --------------------------------------------------
# Charts
# --------------------------------------------------

left, right = st.columns(2)

# ------------------------
# Severity Pie Chart
# ------------------------

severity = {

    "HIGH": 0,

    "MEDIUM": 0,

    "LOW": 0

}

for alert in report["alerts"]:

    sev = alert.get("severity", "LOW")

    if sev in severity:

        severity[sev] += 1

severity_df = pd.DataFrame({

    "Severity": list(severity.keys()),

    "Alerts": list(severity.values())

})

fig = px.pie(

    severity_df,

    values="Alerts",

    names="Severity",

    title="Alert Severity Distribution",

    hole=0.45

)

left.plotly_chart(

    fig,

    use_container_width=True

)

# ------------------------
# MITRE Chart
# ------------------------

mitre = {}

for alert in report["alerts"]:

    technique = alert.get("mitre")

    if technique:

        mitre[technique] = mitre.get(technique, 0) + 1

if mitre:

    mitre_df = pd.DataFrame({

        "Technique": list(mitre.keys()),

        "Count": list(mitre.values())

    })

    fig = px.bar(

        mitre_df,

        x="Technique",

        y="Count",

        title="MITRE ATT&CK Techniques"

    )

    right.plotly_chart(

        fig,

        use_container_width=True

    )

else:

    right.info("No MITRE techniques detected.")

st.markdown("---")

# --------------------------------------------------
# Incident Table
# --------------------------------------------------

st.subheader("Recent Incidents")

rows = []

for incident in report["incidents"]:

    confidence = 0

    if incident["alerts"]:

        confidence = round(

            sum(

                a.get("confidence", 0)

                for a in incident["alerts"]

            )

            /

            len(incident["alerts"])

        )

    rows.append({

        "PID": incident["pid"],

        "Process": incident["process"],

        "Severity": incident["severity"],

        "Alerts": incident["alert_count"],

        "Confidence": confidence

    })

df = pd.DataFrame(rows)

st.dataframe(

    df,

    use_container_width=True,

    hide_index=True

)

st.subheader("🔍 Incident Details")

incident_ids = [incident["id"] for incident in report["incidents"]]

selected = st.selectbox(
    "Select Incident",
    incident_ids
)

incident = next(
    i for i in report["incidents"]
    if i["id"] == selected
)

st.write(f"### Incident #{incident['id']}")
st.write(f"**Process:** {incident['process']}")
st.write(f"**PID:** {incident['pid']}")
st.write(f"**Severity:** {incident['severity']}")
st.write(f"**Total Alerts:** {incident['alert_count']}")

st.markdown("---")

for alert in incident["alerts"]:

    severity = alert.get("severity", "LOW")

    if severity == "HIGH":
        icon = "🔴"

    elif severity == "MEDIUM":
        icon = "🟠"

    else:
        icon = "🟢"

    with st.expander(f"{icon} {alert.get('rule', 'Alert')}"):

        col1, col2 = st.columns(2)

        with col1:

            st.write("### General")

            st.write(f"**Severity:** {severity}")

            st.write(f"**MITRE:** {alert.get('mitre','-')}")

            st.write(f"**Technique:** {alert.get('technique','-')}")

            st.write(f"**Confidence:** {alert.get('confidence',0)}%")

        with col2:

            st.write("### Process")

            st.write(f"**Process:** {alert.get('process','-')}")

            st.write(f"**PID:** {alert.get('pid','-')}")

            st.write(f"**User:** {alert.get('user','-')}")

        if alert.get("description"):

            st.write("### Description")

            st.info(alert["description"])

        if alert.get("command_line"):

            st.write("### Command Line")

            st.code(alert["command_line"])

        if alert.get("path"):

            st.write("### Path")

            st.code(alert["path"])

        if alert.get("remote_ip"):

            st.write("### Network")

            st.write(f"**Remote IP:** {alert['remote_ip']}")

            st.write(f"**Port:** {alert.get('remote_port','-')}")

        if alert.get("recommendation"):

            st.write("### Recommendation")

            st.success(alert["recommendation"])
# --------------------------------------------------
# Alert Details
# --------------------------------------------------

# --------------------------------------------------
# Timeline
# --------------------------------------------------

st.markdown("---")

st.subheader("🕒 Investigation Timeline")

timeline_df = pd.DataFrame(report["timeline"])

if not timeline_df.empty:

    def highlight_severity(row):

        if row["severity"] == "HIGH":

            return [
                "background-color:#ff4b4b;color:white"
            ] * len(row)

        elif row["severity"] == "MEDIUM":

            return [
                "background-color:#ffb84d;color:black"
            ] * len(row)

        elif row["severity"] == "LOW":

            return [
                "background-color:#66bb6a;color:white"
            ] * len(row)

        return [""] * len(row)

    st.dataframe(

        timeline_df.style.apply(

            highlight_severity,

            axis=1

        ),

        use_container_width=True,

        hide_index=True

    )

else:

    st.info("No events found.")

st.markdown("---")

st.subheader("Recent Alerts")

alert_rows = []

for alert in report["alerts"]:

    alert_rows.append({

        "Severity": alert.get("severity"),

        "Rule": alert.get("rule"),

        "Process": alert.get("process"),

        "PID": alert.get("pid"),

        "MITRE": alert.get("mitre"),

        "Confidence": alert.get("confidence")

    })

alert_df = pd.DataFrame(alert_rows)

st.dataframe(

    alert_df,

    use_container_width=True,

    hide_index=True

)