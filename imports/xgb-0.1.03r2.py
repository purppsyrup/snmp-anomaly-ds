import os
import time
import csv
import logging
import configparser
import numpy as np
import psutil
from pysnmp.hlapi import *
from joblib import load
from datetime import datetime, timedelta

log_file = '/var/log/xgb_result.log'
logging.basicConfig(filename=log_file, level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

debug_log_file = '/var/log/xgb_debug-0.1.03.log'
debug_logger = logging.getLogger('debug_logger')
debug_logger.setLevel(logging.DEBUG)
debug_handler = logging.FileHandler(debug_log_file)
debug_handler.setLevel(logging.DEBUG)
debug_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
debug_handler.setFormatter(debug_formatter)
debug_logger.addHandler(debug_handler)
debug_logger.propagate = False

xgb_model = load('xgb-0.1.03.joblib')
scaler = load('scaler-0.1.03.joblib')
label_encoder = load('enc-0.1.03.joblib')

scaler_params = np.load('params-0.1.03.npy', allow_pickle=True).item()

previous_metrics = None

def get_snmp_metrics(host, community_string):
    oids = [
        '1.3.6.1.2.1.2.2.1.10.3',    # ifInOctets11
        '1.3.6.1.2.1.2.2.1.16.3',    # ifOutOctets11
        '1.3.6.1.2.1.2.2.1.11.3',    # ifInUcastPkts11
        '1.3.6.1.2.1.2.2.1.17.3',    # ifOutUcastPkts11
        '1.3.6.1.2.1.6.15.0',        # tcpOutRsts
        '1.3.6.1.2.1.6.10.0',        # tcpInSegs
        '1.3.6.1.2.1.6.11.0',        # tcpOutSegs
        '1.3.6.1.2.1.6.6.0',         # tcpPassiveOpens
        '1.3.6.1.2.1.6.12.0',        # tcpRetransSegs
        '1.3.6.1.2.1.6.9.0',         # tcpCurrEstab
        '1.3.6.1.2.1.6.5.0',         # tcpActiveOpens
        '1.3.6.1.2.1.7.1.0',         # udpInDatagrams
        '1.3.6.1.2.1.7.4.0',         # udpOutDatagrams
        '1.3.6.1.2.1.7.2.0',         # udpNoPorts
        '1.3.6.1.2.1.4.3.0',         # ipInReceives
        '1.3.6.1.2.1.4.9.0',         # ipInDelivers
        '1.3.6.1.2.1.4.10.0',        # ipOutRequests
        '1.3.6.1.2.1.5.1.0',         # icmpInMsgs
        '1.3.6.1.2.1.5.14.0',        # icmpOutMsgs
        '1.3.6.1.2.1.5.16.0',        # icmpOutDestUnreachs
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
    interval = config['SNMP']['interval']
    log_clear = config['SNMP']['log_clear']

    return host, community_string, interval, int(log_clear)

def process_metrics(metrics, previous_metrics, scaler_params):
    if previous_metrics is None:
        debug_logger.debug("No previous metrics to calculate differences.")
        return None, None, metrics, 0

    metrics_diff = np.array(metrics) - np.array(previous_metrics)
    debug_logger.debug(f"Current metrics: {metrics}")
    debug_logger.debug(f"Previous metrics: {previous_metrics}")
    metrics_diff_str = ' '.join(map(str, metrics_diff.flatten()))
    debug_logger.debug(f"Metrics difference: [{metrics_diff_str}]")

    metrics_array = metrics_diff.reshape(1, -1)

    mean = scaler_params['mean']
    scale = scaler_params['scale']
    debug_logger.debug(f"Scaler mean: {mean}")
    debug_logger.debug(f"Scaler scale: {scale}")
    scaled_metrics = (metrics_array - mean) / scale
    debug_logger.debug(f"Scaled metrics: {scaled_metrics}")
    
    start_time = time.time()

    prediction_encoded = xgb_model.predict(scaled_metrics)
    prediction = label_encoder.inverse_transform(prediction_encoded)
    
    end_time = time.time()
    
    prediction_time = end_time - start_time
    debug_logger.debug(f"Prediction time: {prediction_time} seconds")
    
    return prediction[0], metrics_diff, metrics, prediction_time

def append_to_csv(metrics, prediction, csv_file):
    column_names = [
        "ifInOctets11", "ifOutOctets11", "ifInUcastPkts11", "ifOutUcastPkts11",
        "tcpOutRsts", "tcpInSegs", "tcpOutSegs", "tcpPassiveOpens", 
        "tcpRetransSegs", "tcpCurrEstab", "tcpActiveOpens", "udpInDatagrams", 
        "udpOutDatagrams", "udpNoPorts", "ipInReceives", "ipInDelivers", 
        "ipOutRequests", "icmpInMsgs", "icmpOutMsgs", "icmpOutDestUnreachs", 
        "icmpInEchos", "icmpOutEchoReps", "class"
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
        "ifInOctets11_diff", "ifOutOctets11_diff", "ifInUcastPkts11_diff", 
        "ifOutUcastPkts11_diff", "tcpOutRsts_diff", "tcpInSegs_diff", 
        "tcpOutSegs_diff", "tcpPassiveOpens_diff", "tcpRetransSegs_diff", "tcpCurrEstab_diff", 
        "tcpActiveOpens_diff", "udpInDatagrams_diff", "udpOutDatagrams_diff", 
        "udpNoPorts_diff", "ipInReceives_diff", "ipInDelivers_diff", 
        "ipOutRequests_diff", "icmpInMsgs_diff", "icmpOutMsgs_diff", 
        "icmpOutDestUnreachs_diff", "icmpInEchos_diff", "icmpOutEchoReps_diff", 
        "class"
    ]
    
    file_exists = os.path.isfile(csv_file)
    
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        if not file_exists:
            writer.writerow(column_names)
        
        row = list(metrics_diff) + [prediction]
        writer.writerow(row)

def append_resource_usage_to_csv(resource_usage_csv, prediction_time, prediction):
    process = psutil.Process(os.getpid())
    cpu_usage = process.cpu_percent(interval=None)
    memory_info = process.memory_info()
    memory_usage = memory_info.rss / (1024 * 1024)  # Convert to MB
    
    file_exists = os.path.isfile(resource_usage_csv)
    
    with open(resource_usage_csv, mode='a', newline='') as file:
        writer = csv.writer(file)
        
        if not file_exists:
            writer.writerow(["timestamp", "prediction_time", "cpu_usage", "memory_usage", "prediction"])
        
        row = [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), prediction_time, cpu_usage, memory_usage, prediction]
        writer.writerow(row)

def clear_old_logs(days=7):
    log_files = [log_file, debug_log_file]
    now = datetime.now()
    cutoff = now - timedelta(days=days)

    for log in log_files:
        if os.path.isfile(log):
            file_mod_time = datetime.fromtimestamp(os.path.getmtime(log))
            if file_mod_time < cutoff:
                open(log, 'w').close()  # clear
                logging.info(f"Cleared log file: {log}")
                debug_logger.info(f"Cleared log file: {log}")

def main():
    global previous_metrics

    config_file = 'config.ini'
    csv_file = 'xgb-0.1.03.csv'
    diff_csv_file = 'diff-0.1.03.csv'
    resource_usage_csv = 'usage-0.1.03.csv'

    host, community_string, interval, log_clear = read_configuration(config_file)

    while True:
        metrics = get_snmp_metrics(host, community_string)
        prediction, metrics_diff, previous_metrics, prediction_time = process_metrics(metrics, previous_metrics, scaler_params)
        
        if prediction is not None:
            logging.info(f"Prediction: {prediction}")
            append_to_csv(metrics, prediction, csv_file)
            append_diff_to_csv(metrics_diff, prediction, diff_csv_file)
        
        append_resource_usage_to_csv(resource_usage_csv, prediction_time, prediction)
        time.sleep(int(interval))
        clear_old_logs(log_clear)

if __name__ == "__main__":
    main()
