# Intrusion Detection System (IDS)  

This is a signature-based Intrusion Detection System (IDS) designed to detect cyber threats, currently capable of identifying attacks like **port scans**. The system is built using Python and hosted on a **Raspberry Pi 4**. It integrates **threat intelligence feeds** for up-to-date attack signatures and provides real-time monitoring and blocking.  

## Features  

- **Signature-Based Detection**: Identifies known attack patterns, including **port scanning**.  
- **Threat Intelligence Integration**: Regularly updates from external sources to detect new threats.  
- **Traffic Monitoring & Blocking**: Logs and blocks suspicious activity.  
- **Lightweight & Optimized**: Designed to run efficiently on Raspberry Pi 4.  

## Future Updates  

- **Machine Learning Integration**: Enhance detection capabilities using ML models.  
- **Expanded Attack Coverage**: Configure IDS to detect more types of cyber attacks.  

## Installation  

1. Create a virtual environment and install dependencies:  
   ```bash
   python3 -m venv ids_venv
   source ids_venv/bin/activate
   pip install scapy requests twilio
   ```  

## Usage  

To start the IDS, execute the following commands:  

```bash
cd <path/to/ids>
source ids_venv/bin/activate
python ids/update_threat_feeds.py
sudo ids_venv/bin/python ids/ids.py
```

## Configuration  

- **Threat Feed Sources**: Modify `update_threat_feeds.py` to customize threat intelligence sources.  

## Logs & Alerts  

- **Detection Logs**: Threats detected are logged for analysis.  
- **Blocked Traffic**: Suspicious activity is logged and blocked.  
- **WhatsApp & Telegram Alerts**: If an IP address is blocked, an alert message is sent via **WhatsApp or Telegram**. Configure this by setting up the respective API keys.  

## Contributing  

Contributions are welcome! Feel free to suggest improvements or new features.  
