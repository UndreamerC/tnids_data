#!/usr/bin/env python
# coding: utf-8

# In[17]:


import pandas as pd
import os
import subprocess
import platform
import glob
import time
import argparse


# In[18]:


class PrepPcap:
    def __init__(self,file_path,output_path):
        self.path = file_path
        self.tsvpath=output_path
        self.outdir=output_path
        self.tsv_time=None
        self.analysis_time=None
        self.parse_type = None
        self.__prep__()
        
    def pcap2tsv_with_tshark(self):
        print('Parsing with tshark...')
        start_time = time.time()
        fields = "-e frame.time_epoch -e frame.len -e eth.src -e eth.dst -e ip.src -e ip.dst \
        -e ip.proto -e frame.protocols"
        
        cmd =  '"' + self._tshark + '" -r '+ self.path +' -T fields '+ fields +' -E header=y -E occurrence=f > '+self.tsvpath
        subprocess.call(cmd,shell=True)
        end_time = time.time()
        print("tshark parsing complete. File saved as: "+self.tsvpath)

        elapsed_time = end_time - start_time
        self.tsv_time= elapsed_time
        
    def _get_tshark_path(self):
        if platform.system() == 'Windows':
            return 'C:\Program Files\Wireshark\\tshark.exe'
        else:
            system_path = os.environ['PATH']
            for path in system_path.split(os.pathsep):
                filename = os.path.join(path, 'tshark')
                if os.path.isfile(filename):
                    return filename
        return ''
        
    def __prep__(self):
        if not os.path.isfile(self.path):
            print("File: " + self.path + " does not exist")
            raise Exception()

        type = self.path.split('.')[-1]
        self._tshark = self._get_tshark_path()

        if type == "tsv":
            self.parse_type = "tsv"

        elif type == "pcap" or type == 'pcapng':
            # Try parsing via tshark dll of wireshark (faster)
            if os.path.isfile(self._tshark):
                tsv=self.path.split('.')[0]+".tsv"
                self.tsvpath= os.path.join(self.tsvpath, os.path.basename(tsv))
                if not os.path.isfile(self.tsvpath):   
                    tsv_time=self.pcap2tsv_with_tshark()
                self.parse_type = "tsv"
            else:
                print("tshark not found. ")
                raise Exception()
        else:
            print("File: " + self.path + " is not a tsv or pcap file")
            raise Exception()


# In[19]:


def extract_features(tsv_file):
    flow_stats = {}
    start_time = time.time()
    print("Reading PCAP file via tsv")
    packets = pd.read_csv(tsv_file, sep='\t')
    
    for _, row in packets.iterrows():
        src_ip = row['ip.src']
        dst_ip = row['ip.dst']
        protocol = row['frame.protocols']
        frame_time = row['frame.time_epoch']  

        if pd.notna(src_ip) and pd.notna(dst_ip):
            isIP = 1
        else:
            isIP = 0

        flow_key = (src_ip, dst_ip, row['eth.src'], row['eth.dst'])
        if flow_key not in flow_stats:
            flow_stats[flow_key] = {
                'Total': 0,
                'TCP': 0,
                'UDP': 0,
                'ICMP': 0,
                'othProto': 0,
                'ARP': 0,
                'others': 0,
                'first_time': frame_time,  
                'last_time': frame_time    # Initialize with the first time
            }
        flow_stats[flow_key]['Total'] += 1
        flow_stats[flow_key]['last_time'] = frame_time  # Update the last appearance time

        if isIP:
            if isinstance(protocol, str):
                protocol = protocol.split(':')[3]
                if protocol == 'tcp':
                    protocol = 'TCP'
                elif protocol == 'udp':
                    protocol = 'UDP'
                elif protocol == 'icmp':
                    protocol = 'ICMP'
                else:
                    protocol = 'othProto'
            else:
                protocol = 'othProto'
        else:
            if 'arp' in protocol:
                protocol = 'ARP'
            else:
                protocol = 'others'
        
        flow_stats[flow_key][f'{protocol}'] += 1

    records = []
    for (srcip, dstip, srceth, dsteth), stats in flow_stats.items():
        time_interval = float(stats['last_time']) - float(stats['first_time'])
        frequency = stats['Total'] / time_interval if time_interval > 0 else stats['Total']

        record = {
            'ip.src': srcip,
            'ip.dst': dstip,
            'eth.src': srceth,
            'eth.dst': dsteth,
            'Total': stats['Total'],
            'First_Time': stats['first_time'],
            'Last_Time': stats['last_time'],
            'Time_Interval': time_interval,
            'Frequency': frequency
        }
        for proto, count in stats.items():
            if proto not in ['Total', 'first_time', 'last_time']: 
                record[proto] = count
        records.append(record)
    
    df = pd.DataFrame(records)
    df = df.fillna(0).astype({
        'Total': int,
        'TCP': int,
        'UDP': int,
        'ICMP': int,
        'othProto': int,
        'ARP': int,
        'others': int,
        'Time_Interval': float,
        'Frequency': float
    })
    
    end_time = time.time()
    analysis_time = end_time - start_time
    print("Loaded " + str(len(df)) + " data") 
    return df, analysis_time


# In[20]:


def save_to_csv(df, output_file):
    df.to_csv(output_file, index=False)
    print(f"result saved {output_file}")


# In[21]:


def analysis(PP, csv_file):
    df = pd.read_csv(csv_file)
    filename, _ = os.path.splitext(csv_file)

    output = []
    output.append("=== Network Traffic Analysis Report ===")
    
    # Analyze top source and destination addresses using eth.src and eth.dst
    top_src_eth = df['eth.src'].value_counts().head(5)
    top_dst_eth = df['eth.dst'].value_counts().head(5)
    
    output.append("\n1. Top 5 Source Ethernet Addresses (with IP if available):")
    for eth_src in top_src_eth.index:
        ip_src = df[df['eth.src'] == eth_src]['ip.src'].dropna().unique()
        output.append(f"{eth_src} (IP: {', '.join(ip_src) if len(ip_src) > 0 else 'N/A'})")
    
    output.append("\n2. Top 5 Destination Ethernet Addresses (with IP if available):")
    for eth_dst in top_dst_eth.index:
        ip_dst = df[df['eth.dst'] == eth_dst]['ip.dst'].dropna().unique()
        output.append(f"{eth_dst} (IP: {', '.join(ip_dst) if len(ip_dst) > 0 else 'N/A'})")
    
    # Analyze the proportion of TCP, UDP, and ICMP traffic
    total_tcp = df['TCP'].sum()
    total_udp = df['UDP'].sum()
    total_icmp = df['ICMP'].sum()
    total_packets = df['Total'].sum()
    
    output.append("\n3. Traffic Distribution by Protocol:")
    output.append(f"TCP Traffic: {total_tcp / total_packets * 100:.2f}%")
    output.append(f"UDP Traffic: {total_udp / total_packets * 100:.2f}%")
    output.append(f"ICMP Traffic: {total_icmp / total_packets * 100:.2f}%")
    
    # Identify the highest frequency communication pairs using eth.src and eth.dst
    top_frequent_flows = df[['eth.src', 'eth.dst', 'Frequency']].sort_values(by='Frequency', ascending=False).head(5)
    output.append("\n4. Top 5 Most Frequent Flows (Ethernet Addresses):")
    output.append(top_frequent_flows.to_string(index=False))
    
    # Detect potential anomalous behavior (based on frequency and packet count)
    high_freq_threshold = df['Frequency'].quantile(0.95)  # 95th percentile for frequency threshold
    high_freq_flows = df[df['Frequency'] > high_freq_threshold]
    
    if len(high_freq_flows) > 0:
        output.append("\n5. Potential Anomalous Traffic (Frequency above 95%):")
        output.append(high_freq_flows[['eth.src', 'eth.dst', 'Frequency', 'Total']].to_string(index=False))
    else:
        output.append("\n5. No significant anomalous traffic based on high frequency.")
    
    # Analyze abnormal ARP traffic based on eth.src
    arp_by_src = df[df['ARP'] > 0].groupby('eth.src')['ARP'].sum()
    output.append("\n6. ARP Traffic per Ethernet Source:")
    output.append(arp_by_src.to_string())
    
    high_arp_threshold = 100  # Threshold for abnormal ARP traffic
    abnormal_arp_sources = arp_by_src[arp_by_src > high_arp_threshold]
    
    if len(abnormal_arp_sources) > 0:
        output.append(f"\nWarning: Detected abnormal ARP traffic from the following sources (more than {high_arp_threshold} ARP packets):")
        output.append(abnormal_arp_sources.to_string())
    else:
        output.append("\nARP traffic is normal.")
    
    # Analyze time cost
    if PP != None:
        output.append("\n7. Time cost.")
        if PP.tsv_time != None:
            output.append(f"\nTSV processing time: {PP.tsv_time}s.")
        if PP.analysis_time != None:
            output.append(f"\nAnalysis time: {PP.analysis_time}s.")
                
    output_file = f'{filename}_analysis.txt'
    with open(output_file, 'w') as f:
        f.write("\n".join(output))
    
    print(f"Analysis completed. Results saved to {output_file}")


# In[22]:


def gen_features(tsvpath,output_csv,feature_csv):
    tsv_df = pd.read_csv(tsvpath, sep='\t')
    output_df = pd.read_csv(output_csv)

    merge_columns = ['ip.src', 'ip.dst', 'eth.src', 'eth.dst']

    for col in merge_columns:
        if col not in tsv_df.columns or col not in output_df.columns:
            raise ValueError(f"Missing column: {col} in one of the dataframes")
    
    tsv_df[merge_columns] = tsv_df[merge_columns].fillna('0')
    output_df[merge_columns] = output_df[merge_columns].fillna('0')

    merged_df = pd.merge(tsv_df, output_df, on=merge_columns, how='left')
    merged_df.to_csv(feature_csv, index=False) 
    return


# In[23]:


def parser():
    parser = argparse.ArgumentParser(description="Process PCAP files in a directory.")
    parser.add_argument('-d', '--directory', required=True, help="The directory containing PCAP files")
    parser.add_argument('-a', '--analysis', action='store_true', help="Generate summary")
    parser.add_argument('-ds', '--directorys', action='store_true', help="For directorys")
    
    parser.add_argument('-b', '--debug', action='store_true', help="For debug")

    #args = parser.parse_args(['-d', 'Data','-a','-b','-ds'])
    args = parser.parse_args()
    
    return args


# In[24]:


def main():
    args=parser()
    directory = args.directory
    analysis_type = args.analysis
    directorys = args.directorys
    
    debug_type = args.debug

    if directorys:  # Check if the directorys flag is set
    # Get all subdirectories in the main directory
        subdirectories = [os.path.join(directory, d) for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))]
    else:
    # Otherwise, treat the main directory as the only directory to process
        subdirectories = [directory]

    for subdir in subdirectories:
        pcap_files = glob.glob(os.path.join(subdir, '*.pcap*'))
        outdir = os.path.join(subdir, 'output')  
        
        if len(pcap_files) == 0:
            pcap_files = glob.glob(os.path.join(subdir, '*.tsv'))
            if len(pcap_files) == 0:
                print(f"Directory '{subdir}' has no files!\n")
                continue
        else:
            if not os.path.exists(outdir):
                os.makedirs(outdir)
                print(f"Directory '{outdir}' created.")
            print(f"Directory '{outdir}' existed.")
            
        print(f"Start analysis for directory '{subdir}'")
    
        if not debug_type:
            for pcap_path in pcap_files:
                PP = PrepPcap(pcap_path,outdir)
                df,PP.analysis_time=extract_features(PP.tsvpath)
                
                name = os.path.splitext(os.path.basename(pcap_path))[0]
                output_csv = os.path.join(outdir, f'{name}_stats.csv')  
                save_to_csv(df, output_csv)
                if analysis_type:
                    analysis(PP,output_csv)
                feature_csv = os.path.join(outdir, f'{name}_feature.csv')  
                gen_features(PP.tsvpath,output_csv,feature_csv)
        else:
            print("Debug only!\n")
            # for pcap_path in pcap_files:
            #     name = os.path.splitext(os.path.basename(pcap_path))[0]
            #     output_csv = os.path.join(outdir, f'{name}_stats.csv')  
            #     if analysis_type:
            #         analysis(None,output_csv)
    print("Finish all!\n")
if __name__ == "__main__":
    main()

