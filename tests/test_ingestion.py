import requests
import sys
import os

API_URL = "http://localhost:8000/api/ingest/pcap"

def test_ingest(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found at {pcap_path}")
        print("Please place a valid PCAP file there and try again.")
        sys.exit(1)
        
    print(f"Submitting {pcap_path} to {API_URL}...")
    with open(pcap_path, 'rb') as f:
        files = {'file': (os.path.basename(pcap_path), f, 'application/vnd.tcpdump.pcap')}
        response = requests.post(API_URL, files=files)
        
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == "__main__":
    # Expects a PCAP in the datasets folder by default
    default_pcap = os.path.join(os.path.dirname(__file__), "..", "datasets", "sample.pcap")
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else default_pcap
    test_ingest(pcap_file)
