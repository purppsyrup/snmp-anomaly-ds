import pandas as pd
import streamlit as st
import time
from collections import defaultdict
import plotly.express as px

# dict
OID_TO_NAME = {
    'SNMPv2-SMI::mib-2.2.2.1.10.3': 'ifInOctets3',
    'SNMPv2-SMI::mib-2.2.2.1.16.3': 'ifOutOctets3',
    'SNMPv2-SMI::mib-2.2.2.1.11.3': 'ifInUcastPkts3',
    'SNMPv2-SMI::mib-2.2.2.1.17.3': 'ifOutUcastPkts3',
    'SNMPv2-SMI::mib-2.6.15.0': 'tcpOutRsts',
    'SNMPv2-SMI::mib-2.6.10.0': 'tcpInSegs',
    'SNMPv2-SMI::mib-2.6.11.0': 'tcpOutSegs',
    'SNMPv2-SMI::mib-2.6.6.0': 'tcpPassiveOpens',
    'SNMPv2-SMI::mib-2.6.12.0': 'tcpRetransSegs',
    'SNMPv2-SMI::mib-2.6.9.0': 'tcpCurrEstab',
    'SNMPv2-SMI::mib-2.6.5.0': 'tcpActiveOpens',
    'SNMPv2-SMI::mib-2.7.1.0': 'udpInDatagrams',
    'SNMPv2-SMI::mib-2.7.4.0': 'udpOutDatagrams',
    'SNMPv2-SMI::mib-2.7.2.0': 'udpNoPorts',
    'SNMPv2-SMI::mib-2.4.3.0': 'ipInReceives',
    'SNMPv2-SMI::mib-2.4.9.0': 'ipInDelivers',
    'SNMPv2-SMI::mib-2.4.10.0': 'ipOutRequests',
    'SNMPv2-SMI::mib-2.5.1.0': 'icmpInMsgs',
    'SNMPv2-SMI::mib-2.5.14.0': 'icmpOutMsgs',
    'SNMPv2-SMI::mib-2.5.16.0': 'icmpOutDestUnreachs',
    'SNMPv2-SMI::mib-2.5.8.0': 'icmpInEchos',
    'SNMPv2-SMI::mib-2.5.22.0': 'icmpOutEchoReps'
}

# col names
METRIC_NAMES = [
    'ifInOctets3', 'ifOutOctets3', 'ifInUcastPkts3', 'ifOutUcastPkts3',
    'tcpEstabResets', 'tcpInSegs', 'tcpOutSegs', 'tcpActiveOpens',
    'tcpRetransSegs', 'tcpInErrs', 'tcpCurrEstab', 'udpInDatagrams',
    'udpOutDatagrams', 'udpNoPorts', 'ipInReceives', 'ipInDelivers',
    'ipOutRequests', 'icmpInMsgs', 'icmpOutEchos', 'icmpOutDestUnreachs',
    'icmpInEchos', 'icmpOutEchoReps'
]

def read_attack_log():
    try:
        attack_log = pd.read_csv('/var/log/xgb_result.log', delimiter=' - ', names=['Timestamp', 'Prediction'], parse_dates=['Timestamp'])
        attack_log = attack_log[attack_log['Prediction'] != 'Prediction: normal']
        attack_log['Prediction'] = attack_log['Prediction'].str.replace('Prediction: ', '')
        attack_log = attack_log.sort_values(by='Timestamp', ascending=False)
    except FileNotFoundError:
        st.error("Error: File 'verdict.log' not found.")
        return pd.DataFrame(columns=['Timestamp', 'Prediction'])
    return attack_log

def read_debug_log(cycle_window_seconds=4):
    metric_values = defaultdict(dict)
    cycle_start_time = None
    metrics_diff = []
    
    try:
        with open('/var/log/xgb_debug-0.1.03.log', 'r') as file:
            for line in file:
                if 'Retrieved SNMPv2-SMI' in line:
                    line = line.replace('Retrieved ', '') 
                    parts = line.split()
                    timestamp = pd.Timestamp(' '.join(parts[0:2]))
                    oid = parts[3]
                    value = int(parts[-1])

                    if cycle_start_time is None or (timestamp - cycle_start_time).total_seconds() > cycle_window_seconds:
                        cycle_start_time = timestamp

                    if oid in OID_TO_NAME:
                        metric_name = OID_TO_NAME[oid]
                    else:
                        metric_name = oid
                    
                    metric_values[cycle_start_time][metric_name] = value
                
                elif 'Metrics difference' in line:
                    parts = line.split(' - ')
                    timestamp = pd.Timestamp(parts[0])
                    values_part = line.split('Metrics difference: ')[1].strip('[]\n').rstrip('\n')
                    values = list(map(int, values_part.split()))
                    
                    diff = {'Timestamp': timestamp}
                    diff.update(dict(zip(METRIC_NAMES, values)))
                    metrics_diff.append(diff)

    except FileNotFoundError:
        st.error("Error: File 'debug.log' not found.")
    
    return metric_values, metrics_diff

attack_log = read_attack_log()
cycle_values, metrics_diff = read_debug_log()

# wide mode
st.set_page_config(layout="wide")

st.title('SNMP-based Anomaly Detection')

# split layout
col1, col2 = st.columns([1, 3])

with col1:
    st.subheader('Attack Log')

    #table
    if not attack_log.empty:
        st.dataframe(
            attack_log.head(500),
            height=200,
            use_container_width=True
        )
    else:
        st.info("No attack logs found.")

    # graph
    if not attack_log.empty:
        attack_counts = attack_log.groupby([pd.Grouper(key='Timestamp', freq='H'), 'Prediction']).size().reset_index(name='Count')
        fig = px.line(attack_counts, x='Timestamp', y='Count', color='Prediction', title='Number of Attacks Over Time')
        fig.update_layout(yaxis={'title': 'Count of Attacks'}, xaxis={'title': 'Timestamp'})
        st.plotly_chart(fig)
    else:
        st.info("No attack logs found.")

with col2:
    st.subheader('Current Values')
    metrics_diff_df = pd.DataFrame(metrics_diff).sort_values(by='Timestamp', ascending=False)

    if not metrics_diff_df.empty:
        st.dataframe(
            metrics_diff_df.head(200),
            height=200,
            use_container_width=True
        )
    else:
        st.info("No metrics difference logs found.")

    st.subheader('Graphs by MIB Group')
    mib_groups = {
        'Interface': ['ifInOctets3', 'ifOutOctets3', 'ifInUcastPkts3', 'ifOutUcastPkts3'],
        'IP': ['ipInReceives', 'ipInDelivers', 'ipOutRequests'],
        'TCP': ['tcpEstabResets', 'tcpInSegs', 'tcpOutSegs', 'tcpActiveOpens', 'tcpRetransSegs', 'tcpInErrs', 'tcpCurrEstab'],
        'UDP': ['udpInDatagrams', 'udpOutDatagrams', 'udpNoPorts'],
        'ICMP': ['icmpInMsgs', 'icmpOutEchos', 'icmpOutDestUnreachs', 'icmpInEchos', 'icmpOutEchoReps']
    }

    tab_titles = list(mib_groups.keys())
    tabs = st.tabs(tab_titles)

    # plotting per tab
    for tab_title in tab_titles:
        with tabs[tab_titles.index(tab_title)]:
            for metric in mib_groups[tab_title]:
                if metric in metrics_diff_df:
                    fig = px.line(metrics_diff_df, x='Timestamp', y=metric, title=f'{metric} Over Time')
                    fig.update_layout(yaxis={'title': metric, 'tickformat': 'digits'}, xaxis={'title': 'Timestamp'})
                    st.plotly_chart(fig)


refresh = True
if refresh:
    time.sleep(10)
    st.experimental_rerun()