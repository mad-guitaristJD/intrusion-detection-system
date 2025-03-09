import requests

THREAT_FEEDS = [
	"https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
	"https://feodotracker.abuse.ch/downloads.ipblocklist.txt",
	"https://www.spamhouse.org/drop/drop.txt"
]

def update_threat_db():
	malicious_ips = set()
	for url in THREAT_FEEDS:
		try:
			response = requests.get(url)
			if(response.status_code == 200):
				ips = response.text.splitlines()
				for ip in ips:
					if ip and not ip.startswith("#"):
						malicious_ips.add(ip.strip())
		except Exception as e:
			print(f"Error fetching {url}: {e}")

	with open("ids/threat_db.txt", "w") as f:
		for ip in malicious_ips:
			f.write(ip + "\n")

	print(f"Updated threat database with {len(malicious_ips)} IPs.")

update_threat_db()
