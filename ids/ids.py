from scapy.all import sniff, IP, TCP, UDP, Raw
import re
import subprocess
from twilio.rest import Client


ACCOUNT_SID = '[account sid]'
AUTH_TOKEN = '[token]'
TWILIO_WHATSAPP_NUMBER = "whatsapp:+14155238886"
YOUR_WHATSAPP_NUMBER = "whatsapp:+[number]"

client = Client(ACCOUNT_SID, AUTH_TOKEN)

def send_whatsapp_alert(message):
    try:
        client.messages.create(
            from_=TWILIO_WHATSAPP_NUMBER,
            body=message,
            to=YOUR_WHATSAPP_NUMBER
        )
        print(f"WhatsApp Alert Sent: {message}")
    except Exception as e:
        print(f"Error sending WhatsApp alert: {e}")



# Load known attack signatures
SIGNATURES = {
    "SQL Injection": r"(?i)(union select|select.*from|insert into|drop table)",
    "XSS Attack": r"(?i)<script.*?>.*?</script>",
    "Port Scan": "port_scan_detected",  # Placeholder for custom logic
}

# Load known malicious IPs
with open("ids/threat_db.txt") as f:
    MALICIOUS_IPS = set(f.read().splitlines())

# Block IP using iptables
def block_ip(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    print(f"Blocked {ip} using iptables.")

# Packet inspection function
def inspect_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        print(f"Captured Packet from: {src_ip}")
        payload = b""
        
        if packet.haslayer(TCP) and packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            print(f"Payload: {payload}")

        if src_ip in MALICIOUS_IPS:
            print(f"[ALERT] Malicious IP detected: {src_ip}")
            block_ip(src_ip)
            send_whatsapp_alert(f"Blocked malicious IP: {src_ip}")
            return

        for attack, pattern in SIGNATURES.items():
            if re.search(pattern, str(payload)):
                print(f"[ALERT] {attack} detected from {src_ip}")
                send_whatsapp_alert(f"{attack} detected from {src_ip}")
                return


def debug_packet(packet):
        print(packet.summary())

# Capture live packets
print("Starting IDS...")
sniff(filter="ip", prn=inspect_packet, store=False)


