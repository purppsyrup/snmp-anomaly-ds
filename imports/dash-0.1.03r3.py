import pandas as pd
import streamlit as st
import time
from collections import defaultdict

# col name dict
OID_TO_NAME = {
    'SNMPv2-SMI::mib-2.2.2.1.10.3': 'ifInOctets3',
    'SNMPv2-SMI::mib-2.2.2.1.16.3': 'ifOutOctets3',
    'SNMPv2-SMI::mib-2.2.2.1.11.3': 'ifInUcastPkts3',
    'SNMPv2-SMI::mib-2.2.2.1.17.3': 'ifOutUcastPkts3',
    'SNMPv2-SMI::mib-2.6.15.0': 'tcpEstabResets',
    'SNMPv2-SMI::mib-2.6.10.0': 'tcpInSegs',
    'SNMPv2-SMI::mib-2.6.11.0': 'tcpOutSegs',
    'SNMPv2-SMI::mib-2.6.6.0': 'tcpActiveOpens',
    'SNMPv2-SMI::mib-2.6.12.0': 'tcpRetransSegs',
    'SNMPv2-SMI::mib-2.6.9.0': 'tcpInErrs',
    'SNMPv2-SMI::mib-2.6.5.0': 'tcpCurrEstab',
    'SNMPv2-SMI::mib-2.7.1.0': 'udpInDatagrams',
    'SNMPv2-SMI::mib-2.7.4.0': 'udpOutDatagrams',
    'SNMPv2-SMI::mib-2.7.2.0': 'udpNoPorts',
    'SNMPv2-SMI::mib-2.4.3.0': 'ipInReceives',
    'SNMPv2-SMI::mib-2.4.9.0': 'ipInDelivers',
    'SNMPv2-SMI::mib-2.4.10.0': 'ipOutRequests',
    'SNMPv2-SMI::mib-2.5.1.0': 'icmpInMsgs',
    'SNMPv2-SMI::mib-2.5.14.0': 'icmpOutEchos',
    'SNMPv2-SMI::mib-2.5.16.0': 'icmpOutTimestamps',
    'SNMPv2-SMI::mib-2.5.8.0': 'icmpInEchos',
    'SNMPv2-SMI::mib-2.5.22.0': 'icmpInTimestampReps'
}

# diff col names
METRIC_NAMES = [
    'ifInOctets3', 'ifOutOctets3', 'ifInUcastPkts3', 'ifOutUcastPkts3',
    'tcpEstabResets', 'tcpInSegs', 'tcpOutSegs', 'tcpActiveOpens',
    'tcpRetransSegs', 'tcpInErrs', 'tcpCurrEstab', 'udpInDatagrams',
    'udpOutDatagrams', 'udpNoPorts', 'ipInReceives', 'ipInDelivers',
    'ipOutRequests', 'icmpInMsgs', 'icmpOutEchos', 'icmpOutTimestamps',
    'icmpInEchos', 'icmpInTimestampReps'
]

def read_attack_log():
    try:
        attack_log = pd.read_csv('verdict.log', delimiter=' - ', names=['Timestamp', 'Prediction'], parse_dates=['Timestamp'])
        attack_log = attack_log[attack_log['Prediction'] != 'Prediction: normal']
        attack_log = attack_log.sort_values(by='Timestamp', ascending=False)
    except FileNotFoundError:
        st.error("Error: File 'verdict.log' not found.")
        return pd.DataFrame(columns=['Timestamp', 'Prediction'])
    return attack_log

def read_debug_log(cycle_window_seconds=5):
    metric_values = defaultdict(dict)
    cycle_start_time = None
    metrics_diff = []
    
    try:
        with open('debug.log', 'r') as file:
            for line in file:
                if 'Retrieved SNMPv2-SMI' in line:
                    line = line.replace('Retrieved ', '') 
                    parts = line.split()
                    timestamp = pd.Timestamp(' '.join(parts[0:2]))
                    oid = parts[3]
                    value = int(parts[-1])

                    # Determine the cycle start time
                    if cycle_start_time is None or (timestamp - cycle_start_time).total_seconds() > cycle_window_seconds:
                        cycle_start_time = timestamp

                    # Update the cycle values
                    if oid in OID_TO_NAME:
                        metric_name = OID_TO_NAME[oid]
                    else:
                        metric_name = oid
                    
                    metric_values[cycle_start_time][metric_name] = value
                
                elif 'Metrics difference' in line:
                    parts = line.split(' - ')
                    timestamp = pd.Timestamp(parts[0])
                    # Extract the part after 'Metrics difference: '
                    values_part = line.split('Metrics difference: ')[1]
                    values = list(map(int, values_part.strip('[]').split()))
                    diff = {'Timestamp': timestamp}
                    diff.update(dict(zip(METRIC_NAMES, values)))
                    metrics_diff.append(diff)

    except FileNotFoundError:
        st.error("Error: File 'debug.log' not found.")
    
    return metric_values, metrics_diff

attack_log = read_attack_log()
cycle_values, metrics_diff = read_debug_log()

# Streamlit app
st.title('SNMP-based Anomaly Detection')

# Attack Log Section
st.subheader('Attack Log')
if not attack_log.empty:
    st.dataframe(
        attack_log.head(500),  # Displaying the first 10 rows
        height=200,
        use_container_width=True
    )
else:
    st.info("No attack logs found.")

# Metrics Difference Section
st.subheader('Current Values')
metrics_diff_df = pd.DataFrame(metrics_diff).sort_values(by='Timestamp', ascending=False)

if not metrics_diff_df.empty:
    st.dataframe(
        metrics_diff_df.head(100),  # Displaying the first 10 rows
        height=200,
        use_container_width=True
    )
else:
    st.info("No metrics difference logs found.")

# Metrics Table Section
st.subheader('Cumulative Values')

# Convert cycle_values to a list of dictionaries
metrics_data = []
for cycle_start, values in cycle_values.items():
    row = {'Cycle Start': cycle_start}
    row.update(values)
    metrics_data.append(row)

# Create a dataframe for metrics
metrics_df = pd.DataFrame(metrics_data).sort_values(by='Cycle Start', ascending=False)

if not metrics_df.empty:
    st.dataframe(
        metrics_df.head(100),  # Displaying the first 10 rows
        height=200,
        use_container_width=True
    )
else:
    st.info("No SNMP metrics found.")

st_autorefresh = st.button("Auto-Refresh")
if st_autorefresh:
    time.sleep(5)
    st.experimental_rerun()