#import necessary packages
from fastapi import FastAPI, UploadFile, File
from scapy.all import rdpcap
import tempfile
import os
import pandas as pd
import numpy as np
from scapy.all import rdpcap
from collections import defaultdict

def extract_features(packets):
    # Group packets by flow (src_ip, dst_ip pair)
    flows = defaultdict(list)
    
    for pkt in packets:
        # Only process packets that have IP layer
        if pkt.haslayer('IP'):
            src = pkt['IP'].src
            dst = pkt['IP'].dst
            size = len(pkt)
            timestamp = float(pkt.time)
            
            # Use sorted tuple so A->B and B->A are same flow
            flow_key = tuple(sorted([src, dst]))
            flows[flow_key].append({
                'timestamp': timestamp,
                'size': size,
                'src': src,
                'dst': dst
            })
    
    # Now calculate features per flow
    flow_features = []
    
    for (ip1, ip2), pkts in flows.items():
        timestamps = [p['timestamp'] for p in pkts]
        sizes = [p['size'] for p in pkts]
        
        # Sort by time
        timestamps.sort()
        
        # Calculate inter-arrival times (gaps between packets)
        intervals = [timestamps[i+1] - timestamps[i] 
                    for i in range(len(timestamps)-1)]
        
        flow_features.append({
            'ip_pair': f"{ip1} <-> {ip2}",
            'packet_count': len(pkts),
            'avg_packet_size': round(np.mean(sizes), 2),
            'total_bytes': sum(sizes),
            'avg_interval': round(np.mean(intervals), 4) if intervals else 0,
            'interval_variance': round(np.var(intervals), 4) if intervals else 0,
            'duration': round(max(timestamps) - min(timestamps), 4)
        })
    
    return pd.DataFrame(flow_features)
app = FastAPI()
@app.get("/")
def root():
    return {"status": "NetWatch alive"}
@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    packets = rdpcap(tmp_path)
    os.remove(tmp_path)

    # Extract features
    df = extract_features(packets)
    
    return {
        "filename": file.filename,
        "total_packets": len(packets),
        "total_flows": len(df),
        "flows": df.to_dict(orient="records")
    }