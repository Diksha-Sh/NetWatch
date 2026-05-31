#import necessary packages
from fastapi import FastAPI, UploadFile, File
from scapy.all import rdpcap
import tempfile
import os

app = FastAPI()
@app.get("/")
def root():
    return {"status": "NetWatch alive"}
@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    # Read with Scapy(the pcap files)
    packets = rdpcap(tmp_path)

    #Delete temp file
    os.remove(tmp_path)

    # Extract basic info from first 5 packets
    packet_info = []
    for pkt in packets[:5]:
        packet_info.append(str(pkt.summary()))

    return {
        "filename": file.filename,
        "total_packets": len(packets),
        "first_5_packets": packet_info
    }a