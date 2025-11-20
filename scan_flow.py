import os 
import pandas as pd

from scapy.all import rdpcap, wrpcap 
from datetime import datetime

from config import FLOW_PATH
from config import PCAP_PATH
from config import PCAP_FLOWS_PATH


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
            print(f"Adding packet with time: {pkt.time} - Start time: {timestamp_start} - End time: {timestamp_start + duration}")
            flow_packets.append(pkt)

    wrpcap(out_file, flow_packets)

    return len(flow_packets), out_file


def iter_flows(packets, csv_flow_name):
    """

    For each flow defined in the CSV file, extract and save the corresponding packets to individual pcap files.

    """
        
    flow_file_path = os.path.join(PCAP_FLOWS_PATH, csv_flow_name)
    print(f"Processing file: {flow_file_path}")

    df = pd.read_csv(flow_file_path) 
    df = df[df['duration'] > 0]
    
    print(f"Number of flows with duration > 0: {len(df)}")

    for index, row in df.iterrows():
        ip_src = row['src_ip']
        ip_dest = row['dst_ip']
        port_src = row['src_port']
        port_dest = row['dst_port']

        duration = row['duration']
        timestamp_str = row['timestamp']

        print(f"[{index}] Processing flow {ip_src}:{port_src} <-> {ip_dest}:{port_dest} - timestamp: {timestamp_str}")

        time = datetime.strptime(timestamp_str,"%Y-%m-%d %H:%M:%S.%f")
        timestamp = datetime.timestamp(time)

        dir_name = csv_flow_name.split(".")[0]
        out_file = f"{FLOW_PATH}/{dir_name}/{dir_name}_flow_{index}.pcap"
        os.makedirs(f"{FLOW_PATH}/{dir_name}", exist_ok=True)
    
        _, _ = extract_and_save_flow(packets = packets,
                                    out_file=out_file,
                                    ip_src=ip_src,
                                    ip_dst=ip_dest,
                                    port_src=port_src,
                                    port_dst=port_dest,
                                    timestamp_start=timestamp,
                                    duration=duration,
                                    protocol="TCP")
        
        print(f"[{index}] End flow {ip_src}:{port_src} <-> {ip_dest}:{port_dest} - timestamp: {timestamp_str} - Output: {out_file.split('/')[-1]}")
        


def iter_pcap(): 
    """
    For each pcap file in PCAP_PATH, read the packets and iterate over flows defined in corresponding CSV files.
    """

    for filename in os.listdir(PCAP_PATH):
        if not filename.endswith('.pcap'):
            continue
        csv_flow_name = filename.split(".")[0] + "_flows.csv"
        pcap_file_path = os.path.join(PCAP_PATH, filename)
        print(f"----- Start PCAP: {pcap_file_path} -----")
        packets = rdpcap(pcap_file_path)
        iter_flows(packets, csv_flow_name)
        print(f"----- End pcap {filename} -----")

def main(): 
    iter_pcap()

if __name__ == "__main__":
    main()
    

    

