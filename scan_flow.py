import os 
import sys
import time
import pandas as pd

from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import rdpcap, wrpcap 
from datetime import datetime

from config import FLOW_PATH
from config import PCAP_PATH
from config import PCAP_FLOWS_PATH

# Lock per output thread-safe
print_lock = Lock()

def safe_print(message):
    """Print thread-safe"""
    with print_lock:
        print(message)


def validate_max_workers(requested_workers):
    """
    Validate and limit the number of threads to the maximum available on the system.   
    Args:
        requested_workers: Number of requested threads
        
    Returns:
        Validated number of threads (limited to the maximum available)
    """
    
    cpu_count = os.cpu_count() or 1
    # Maximum recommended: 2x the number of CPUs (for I/O bound tasks)
    max_recommended = cpu_count * 2
    
    if requested_workers > max_recommended:
        safe_print(f"Warning: Request {requested_workers} thread, but the system has only {cpu_count} CPU.")
        safe_print(f"Limiting to {max_recommended} threads (2x CPU) to avoid overload.")
        return max_recommended
    
    if requested_workers < 1:
        safe_print(f"Warning: Number of threads must be >= 1. Using 1 thread.")
        return 1
    
    return requested_workers


def extract_and_save_flow(packets, out_file: str, ip_src: str, ip_dst: str, port_src: int, port_dst: int, timestamp_start: float, duration: float, protocol: str="TCP"):
    
    flow_packets = []

    for pkt in packets:
        forward = False
        backward = False
        if not pkt.haslayer("IP"):
            continue
        if protocol == "TCP" and not pkt.haslayer("TCP"):
            continue
        if protocol == "UDP" and not pkt.haslayer("UDP"):
            continue
        
        ip = pkt["IP"]
        l4 = pkt[protocol]

        if ((pkt.time <= (timestamp_start + duration)) and (pkt.time >= timestamp_start)):
            forward = (
                ip.src == ip_src and ip.dst == ip_dst and
                l4.sport == port_src and l4.dport == port_dst
            )

            backward = (
                ip.src == ip_dst and ip.dst == ip_src and
                l4.sport == port_dst and l4.dport == port_src
            )        
        if forward or backward:
            safe_print(f"Adding packet with time: {pkt.time} - Start time: {timestamp_start} - End time: {timestamp_start + duration}")
            flow_packets.append(pkt)

    wrpcap(out_file, flow_packets)

    return len(flow_packets), out_file


def process_single_flow(packets, index, row, csv_flow_name):
    """
    Process a single flow - executed in a thread.
    Each thread processes one row (flow) of the CSV independently.
    """
    ip_src = row['src_ip']
    ip_dest = row['dst_ip']
    port_src = row['src_port']
    port_dest = row['dst_port']
    duration = row['duration']
    timestamp_str = row['timestamp']

    safe_print(f"[{index}] Processing flow {ip_src}:{port_src} <-> {ip_dest}:{port_dest} - timestamp: {timestamp_str}")

    time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
    timestamp = datetime.timestamp(time)

    dir_name = csv_flow_name.split(".")[0]
    out_file = f"{FLOW_PATH}/{dir_name}/{dir_name}_flow_{index}.pcap"
    os.makedirs(f"{FLOW_PATH}/{dir_name}", exist_ok=True)

    _, _ = extract_and_save_flow(
        packets=packets,
        out_file=out_file,
        ip_src=ip_src,
        ip_dst=ip_dest,
        port_src=port_src,
        port_dst=port_dest,
        timestamp_start=timestamp,
        duration=duration,
        protocol="TCP"
    )
    
    safe_print(f"[{index}] End flow {ip_src}:{port_src} <-> {ip_dest}:{port_dest} - timestamp: {timestamp_str} - Output: {out_file.split('/')[-1]}")
    return index


def iter_flows(packets, csv_flow_name, max_workers=4):
    """
    For each flow defined in the CSV file, extract and save the corresponding packets to individual pcap files.
    Use multithreading: each thread processes one flow (CSV row) concurrently.

    Args:
        packets: Packets from the pcap file
        csv_flow_name: Name of the CSV file containing the flows
        max_workers: Number of threads to use (default: 4)
    """
        
    flow_file_path = os.path.join(PCAP_FLOWS_PATH, csv_flow_name)
    safe_print(f"Processing file: {flow_file_path}")

    df = pd.read_csv(flow_file_path) 
    df = df[df['duration'] > 0]
    
    # Validate the number of threads
    validated_workers = validate_max_workers(max_workers)
    
    safe_print(f"Number of flows with duration > 0: {len(df)}")
    safe_print(f"Using {validated_workers} threads for parallel processing (CPU count: {os.cpu_count()})")

    # ThreadPoolExecutor automatically manages the task queue
    # ensuring that each flow is processed only once
    with ThreadPoolExecutor(max_workers=validated_workers) as executor:
        # Submit all flow as independent tasks
        futures = {
            executor.submit(process_single_flow, packets, index, row, csv_flow_name): index
            for index, row in df.iterrows()
        }
        
        # Wait for completion and handle any errors
        completed = 0
        for future in as_completed(futures):
            try:
                result = future.result()
                completed += 1
                if completed % 10 == 0:
                    safe_print(f"Progress: {completed}/{len(df)} flows completed")
            except Exception as e:
                index = futures[future]
                safe_print(f"Error processing flow {index}: {str(e)}")
    
    safe_print(f"Completed: {completed}/{len(df)} flows processed")
        


def iter_pcap(max_workers=1): 
    """
    For each pcap file in PCAP_PATH, read the packets and iterate over flows defined in corresponding CSV files.
    
    Args:
        max_workers: Number of threads for parallel processing (default: 1)
    """

    for filename in os.listdir(PCAP_PATH):
        if not filename.endswith('.pcap'):
            continue
        csv_flow_name = filename.split(".")[0] + "_flows.csv"
        pcap_file_path = os.path.join(PCAP_PATH, filename)
        safe_print(f"----- Start PCAP: {pcap_file_path} -----")
        packets = rdpcap(pcap_file_path)
        iter_flows(packets, csv_flow_name, max_workers=max_workers)
        safe_print(f"----- End pcap {filename} -----")

def main(max_workers=1): 
    """
    Main entry point.
    
    Args:
        max_workers: Number of threads to use (default: 1)
    """
    start_time = time.time()
    
    validated_workers = validate_max_workers(max_workers)
    safe_print(f"Starting multithread processing with {validated_workers} workers")
    iter_pcap(max_workers=validated_workers)
    
    elapsed_time = time.time() - start_time
    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time % 3600) // 60)
    seconds = elapsed_time % 60
    
    safe_print("="*50)
    safe_print("Processing completed!")
    safe_print(f"Total execution time: {hours:02d}h {minutes:02d}m {seconds:05.2f}s")
    safe_print(f"Total execution time (seconds): {elapsed_time:.2f}s")
    safe_print("="*50)

if __name__ == "__main__":
    try:
        workers = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    except ValueError:
        print(f"Error: '{sys.argv[1]}' is not a valid number. Using default: 1 thread.")
        workers = 1
    
    main(max_workers=workers)



    

    

