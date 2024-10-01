import os
import time
import csv
import logging
import configparser
import numpy as np
from pysnmp.hlapi import *
from joblib import load

log_file = '/home/bordeauxsyrup/Documents/PERSONAL FILES/code/xgb_project/verdict.log'
logging.basicConfig(filename=log_file, level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

debug_log_file = '/home/bordeauxsyrup/Documents/PERSONAL FILES/code/xgb_project/debug.log'
debug_logger = logging.getLogger('debug_logger')
debug_logger.setLevel(logging.DEBUG)
debug_handler = logging.FileHandler(debug_log_file)
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
debug_handler.setFormatter(debug_formatter)
debug_logger.addHandler(debug_handler)
debug_logger.propagate = False

xgb_model = load('xgb-1.0.z1.joblib')
scaler = load('scaler-1.0.z1.joblib')
label_encoder = load('enc-1.0.z1.joblib')

scaler_params = np.load('params-1.0.z1.npy', allow_pickle=True).item()

previous_metrics = None

def get_snmp_metrics(host, community_string):
    oids = [
        '1.3.6.1.2.1.2.2.1.10.3',    # ifInOctets for wlan0
        '1.3.6.1.2.1.2.2.1.16.3',    # ifOutOctets for wlan0
        '1.3.6.1.2.1.2.2.1.13.3',    # ifOutDiscards for wlan0
        '1.3.6.1.2.1.2.2.1.11.3',    # ifInUcastPkts for wlan0
        '1.3.6.1.2.1.2.2.1.12.3',    # ifInNUcastPkts for wlan0
        '1.3.6.1.2.1.2.2.1.4.3',     # ifInDiscards for wlan0
        '1.3.6.1.2.1.2.2.1.17.3',    # ifOutUcastPkts for wlan0
        '1.3.6.1.2.1.2.2.1.18.3',    # ifOutNUcastPkts for wlan0
        '1.3.6.1.2.1.6.15.0',        # tcpOutRsts
        '1.3.6.1.2.1.6.10.0',        # tcpInSegs
        '1.3.6.1.2.1.6.11.0',        # tcpOutSegs
        '1.3.6.1.2.1.6.6.0',         # tcpPassiveOpens
        '1.3.6.1.2.1.6.12.0',        # tcpRetransSegs
        '1.3.6.1.2.1.6.9.0',         # tcpCurrEstab
        '1.3.6.1.2.1.6.8.0',         # tcpEstabResets
        '1.3.6.1.2.1.6.5.0',         # tcpActiveOpens
        '1.3.6.1.2.1.7.1.0',         # udpInDatagrams
        '1.3.6.1.2.1.7.4.0',         # udpOutDatagrams
        '1.3.6.1.2.1.7.3.0',         # udpInErrors
        '1.3.6.1.2.1.7.2.0',         # udpNoPorts
        '1.3.6.1.2.1.4.3.0',         # ipInReceives
        '1.3.6.1.2.1.4.9.0',         # ipInDelivers
        '1.3.6.1.2.1.4.10.0',        # ipOutRequests
        '1.3.6.1.2.1.4.14.0',        # ipOutDiscards
        '1.3.6.1.2.1.4.13.0',        # ipInDiscards
        '1.3.6.1.2.1.4.7.0',         # ipForwDatagrams
        '1.3.6.1.2.1.4.19.0',        # ipOutNoRoutes
        '1.3.6.1.2.1.4.4.0',         # ipInAddrErrors
        '1.3.6.1.2.1.5.1.0',         # icmpInMsgs
        '1.3.6.1.2.1.5.3.0',         # icmpInDestUnreachs
        '1.3.6.1.2.1.5.14.0',        # icmpOutMsgs
        '1.3.6.1.2.1.5.21.0',        # icmpOutDestUnreachs
        '1.3.6.1.2.1.5.8.0',         # icmpInEchos
        '1.3.6.1.2.1.5.22.0',        # icmpOutEchoReps
    ]

    metrics = []
    for oid in oids:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community_string, mpModel=0),
                   UdpTransportTarget((host, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid))
            )
        )

        if errorIndication:
            debug_logger.error(f"SNMP error: {errorIndication}")
            continue
        if errorStatus:
            debug_logger.error(f"SNMP error: {errorStatus} at {errorIndex}")
            continue

        for varBind in varBinds:
            metric_value = int(varBind[1])
            debug_logger.debug(f"Retrieved {varBind[0].prettyPrint()} with value {metric_value}")
            metrics.append(metric_value)

    return metrics

def read_configuration(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    host = config['SNMP']['host']
    community_string = config['SNMP']['community_string']

    return host, community_string

def process_metrics(metrics, previous_metrics, scaler_params):
    if previous_metrics is None:
        debug_logger.debug("No previous metrics to calculate differences.")
        return None, None, metrics

    metrics_diff = np.array(metrics) - np.array(previous_metrics)
    debug_logger.debug(f"Current metrics: {metrics}")
    debug_logger.debug(f"Previous metrics: {previous_metrics}")
    debug_logger.debug(f"Metrics difference: {metrics_diff}")

    metrics_array = metrics_diff.reshape(1, -1)
    
    mean = scaler_params['mean']
    scale = scaler_params['scale']
    debug_logger.debug(f"Scaler mean: {mean}")
    debug_logger.debug(f"Scaler scale: {scale}")
    scaled_metrics = (metrics_array - mean) / scale
    debug_logger.debug(f"Scaled metrics: {scaled_metrics}")
    
    prediction_encoded = xgb_model.predict(scaled_metrics)
    prediction = label_encoder.inverse_transform(prediction_encoded)
    
    return prediction[0], metrics_diff, metrics

def append_to_csv(metrics, prediction, csv_file):
    column_names = [
        "ifInOctets11", "ifOutOctets11", "ifOutDiscards11", 
        "ifInUcastPkts11", "ifInNUcastPkts11", "ifInDiscards11", 
        "ifOutUcastPkts11", "ifOutNUcastPkts11", "tcpOutRsts",
        "tcpInSegs", "tcpOutSegs", "tcpPassiveOpens", "tcpRetransSegs",
        "tcpCurrEstab", "tcpEstabResets", "tcpActiveOpens", "udpInDatagrams",
        "udpOutDatagrams", "udpInErrors", "udpNoPorts", "ipInReceives",
        "ipInDelivers", "ipOutRequests", "ipOutDiscards", "ipInDiscards",
        "ipForwDatagrams", "ipOutNoRoutes", "ipInAddrErrors", "icmpInMsgs",
        "icmpInDestUnreachs", "icmpOutMsgs", "icmpOutDestUnreachs", "icmpInEchos",
        "icmpOutEchoReps", "class"
    ]
    
    file_exists = os.path.isfile(csv_file)
    
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        if not file_exists:
            writer.writerow(column_names)
        
        row = metrics + [prediction]
        writer.writerow(row)

def append_diff_to_csv(metrics_diff, prediction, csv_file):
    column_names = [
        "ifInOctets11_diff", "ifOutOctets11_diff", "ifOutDiscards11_diff", 
        "ifInUcastPkts11_diff", "ifInNUcastPkts11_diff", "ifInDiscards11_diff", 
        "ifOutUcastPkts11_diff", "ifOutNUcastPkts11_diff", "tcpOutRsts_diff",
        "tcpInSegs_diff", "tcpOutSegs_diff", "tcpPassiveOpens_diff", "tcpRetransSegs_diff",
        "tcpCurrEstab_diff", "tcpEstabResets_diff", "tcpActiveOpens_diff", "udpInDatagrams_diff",
        "udpOutDatagrams_diff", "udpInErrors_diff", "udpNoPorts_diff", "ipInReceives_diff",
        "ipInDelivers_diff", "ipOutRequests_diff", "ipOutDiscards_diff", "ipInDiscards_diff",
        "ipForwDatagrams_diff", "ipOutNoRoutes_diff", "ipInAddrErrors_diff", "icmpInMsgs_diff",
        "icmpInDestUnreachs_diff", "icmpOutMsgs_diff", "icmpOutDestUnreachs_diff", "icmpInEchos_diff",
        "icmpOutEchoReps_diff", "class"
    ]
    
    file_exists = os.path.isfile(csv_file)
    
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        if not file_exists:
            writer.writerow(column_names)
        
        row = list(metrics_diff) + [prediction]
        writer.writerow(row)

def main():
    global previous_metrics

    config_file = '/etc/xgb_nids/config.ini'
    csv_file = 'xgb-1.0.z1.csv'
    diff_csv_file = 'diff-1.0.z1.csv'
    
    while True:
        host, community_string = read_configuration(config_file)
        metrics = get_snmp_metrics(host, community_string)
        prediction, metrics_diff, previous_metrics = process_metrics(metrics, previous_metrics, scaler_params)
        
        if prediction is not None:
            logging.info(f"Prediction: {prediction}")
            append_to_csv(metrics, prediction, csv_file)
            append_diff_to_csv(metrics_diff, prediction, diff_csv_file)
        
        time.sleep(5)

if __name__ == "__main__":
    main()
