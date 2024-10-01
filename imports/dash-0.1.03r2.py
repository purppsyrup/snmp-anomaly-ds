import pandas as pd
import streamlit as st
from collections import defaultdict

# OID to Name Mapping
OID_TO_NAME = {
    'SNMPv2-SMI::mib-2.2.2.1.10.3': 'ifInOctets3',
    'SNMPv2-SMI::mib-2.2.2.1.13.3': 'ifInDiscards3',
    'SNMPv2-SMI::mib-2.2.2.1.16.3': 'ifOutOctets3',
    'SNMPv2-SMI::mib-2.6.10.0': 'tcpInSegs',
    'SNMPv2-SMI::mib-2.6.12.0': 'tcpRetransSegs',
    'SNMPv2-SMI::mib-2.6.15.0': 'tcpEstabResets',
    'SNMPv2-SMI::mib-2.7.1.0': 'udpInDatagrams',
    'SNMPv2-SMI::mib-2.7.4.0': 'udpOutDatagrams',
    'SNMPv2-SMI::mib-2.7.2.0': 'udpNoPorts',
    'SNMPv2-SMI::mib-2.4.3.0': 'ipInReceives',
    'SNMPv2-SMI::mib-2.4.9.0': 'ipInDelivers',
    'SNMPv2-SMI::mib-2.4.10.0': 'ipOutRequests',
    'SNMPv2-SMI::mib-2.4.13.0': 'ipInDiscards',
    'SNMPv2-SMI::mib-2.4.8.0': 'ipInAddrErrors',
    'SNMPv2-SMI::mib-2.4.11.0': 'ipOutDiscards',
    'SNMPv2-SMI::mib-2.5.1.0': 'icmpInMsgs',
    'SNMPv2-SMI::mib-2.5.2.0': 'icmpOutMsgs',
    'SNMPv2-SMI::mib-2.5.3.0': 'icmpInDestUnreachs',
    'SNMPv2-SMI::mib-2.5.4.0': 'icmpOutDestUnreachs',
    'SNMPv2-SMI::mib-2.5.8.0': 'icmpInEchos',
    'SNMPv2-SMI::mib-2.5.9.0': 'icmpOutEchoReps'
}

# Read the attack log
def read_attack_log():
    try:
        attack_log = pd.read_csv('verdict.log', delimiter=' - ', names=['Timestamp', 'Prediction'], parse_dates=['Timestamp'])
        attack_log = attack_log.sort_values(by='Timestamp', ascending=False)
    except FileNotFoundError:
        st.error("Error: File 'verdict.log' not found.")
        return pd.DataFrame(columns=['Timestamp', 'Prediction'])
    return attack_log

# Read the debug log and parse metrics
def read_debug_log(cycle_window_seconds=5):
    metric_values = defaultdict(dict)
    cycle_start_time = None
    
    try:
        with open('debug.log', 'r') as file:
            for line in file:
                if 'Retrieved SNMPv2-SMI' in line:
                    line = line.replace('Retrieved ', '')  # Remove "Retrieved " from the line
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

    except FileNotFoundError:
        st.error("Error: File 'debug.log' not found.")
    
    return metric_values

# Load data
attack_log = read_attack_log()
cycle_values = read_debug_log()

# Streamlit app
st.title('Intrusion Detection System')

# Attack Log Section
st.subheader('Attack Log')
if not attack_log.empty:
    st.dataframe(
        attack_log.head(10),  # Displaying the first 10 rows
        height=200,
        use_container_width=True
    )
else:
    st.info("No attack logs found.")

# Metrics Table Section
st.subheader('SNMP Metrics')

# Convert cycle_values to a list of dictionaries
metrics_data = []
for cycle_start, values in cycle_values.items():
    row = {'Cycle Start': cycle_start}
    row.update(values)
    metrics_data.append(row)

# Create a dataframe for metrics
metrics_df = pd.DataFrame(metrics_data)

# Sort metrics_df by Cycle Start (newest first)
metrics_df = metrics_df.sort_values(by='Cycle Start', ascending=False)

# Display the dataframe
if not metrics_df.empty:
    st.dataframe(
        metrics_df.head(100),  # Displaying the first 100 rows
        height=200,
        use_container_width=True
    )
else:
    st.info("No SNMP metrics found.")
