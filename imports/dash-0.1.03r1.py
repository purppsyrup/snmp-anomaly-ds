import pandas as pd
import streamlit as st

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
def read_debug_log():
    metric_values = {}
    
    try:
        with open('debug.log', 'r') as file:
            for line in file:
                if 'Retrieved SNMPv2-SMI' in line:
                    line = line.replace('Retrieved ', '')  # Remove "Retrieved " from the line
                    parts = line.split()
                    timestamp = ' '.join(parts[0:2])
                    oid = parts[3]
                    value = int(parts[-1])
                    
                    # print(f"Timestamp: {timestamp}, OID: {oid}, Value: {value}")
                    
                    if timestamp not in metric_values:
                        metric_values[timestamp] = {}
                    
                    # Assuming you have a dictionary OID_TO_NAME mapping OIDs to names
                    if oid in OID_TO_NAME:
                        metric_name = OID_TO_NAME[oid]
                        metric_values[timestamp][metric_name] = value  # Store the metric value
                    else:
                        metric_values[timestamp][oid] = value  # Store the OID if name not found
    except FileNotFoundError:
        st.error("Error: File 'debug.log' not found.")
    
    return metric_values


# Load data
attack_log = read_attack_log()
metric_values = read_debug_log()

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

# Convert metric_values to a list of dictionaries
metrics_data = []
for timestamp, values in metric_values.items():
    row = {'Timestamp': pd.to_datetime(timestamp)}
    row.update(values)  # Add all metric values for the current timestamp
    metrics_data.append(row)

# Create a dataframe for metrics
metrics_df = pd.DataFrame(metrics_data)

# Ensure all metrics are included and displayed correctly
all_metrics = list(OID_TO_NAME.values())
metrics_df = metrics_df.reindex(columns=['Timestamp'] + all_metrics)

# Order metrics table by newest timestamp
metrics_df = metrics_df.sort_values(by='Timestamp', ascending=False)

# Display the dataframe
if not metrics_df.empty:
    st.dataframe(
        metrics_df.head(100),  # Displaying the first 10 rows
        height=200,
        use_container_width=True
    )
else:
    st.info("No SNMP metrics found.")
