import os, sys
import xml.sax
from datetime import datetime

max_reports = 5
networks = " ".join(sys.argv[1:])
nmap_params = "-p 443 --script ./nse/ms-exchange-version.nse --script-args=showcves,http.max-cache-size=10000000"
out_file = "out/%s.xml" % datetime.now().strftime("%Y-%m-%d_%H-%M")
md_file = "scans/%s.md" % datetime.now().strftime("%Y-%m-%d_%H-%M")

if len(networks) < 7:
	print("Usage: %s HOST [HOST...]" % (sys.argv[0]))
	exit(6)

# Run the scan
nmap_cmd = f"nmap {nmap_params} -oX {out_file} {networks}"
if os.system(nmap_cmd) > 0:
	exit(1)

# the xml parser
class Parser(xml.sax.ContentHandler):
	def __init__(self):
		self.current = {}
		self.hosts = []
		self.table_tags = 0
		self.elem_key = ''

	def startElement(self, tag, attrs):
		if tag == 'host':
			self.current = { 'address': None, 'name': '', 'port': False, 'check': False, 'exchange': None, 'cves':[], }

		elif tag == 'address' and attrs.get('addrtype') == 'ipv4':
			self.current['address'] = attrs.get('addr')

		elif tag == 'hostname' and 'name' in self.current:
			self.current['name'] = attrs.get('name')

		elif tag == 'port':
			self.current['port'] = True

		elif tag == 'state' and self.current['port'] and attrs.get('state') == 'open':
			self.current['check'] = True

		elif tag == 'script' and self.current['check'] and attrs.get('output')[:5].lower() != 'error':
			self.current['exchange'] = {}

		elif tag == 'table':
			self.table_tags += 1
			# cves are in a encasulated table
			if self.table_tags == 3:
				self.current['cves'].append({})

		elif tag == 'elem':
			self.elem_key = attrs.get('key')

	def characters(self, data):
		s = data.strip()
		if len(self.elem_key) <= 0:
			return

		# exchange information
		if self.table_tags == 1:
			self.current['exchange'][self.elem_key] = self.current['exchange'][self.elem_key] + s if self.elem_key in self.current['exchange'] else s
			self.elem_key = ''
		# cves
		elif self.table_tags == 3:
			self.current['cves'][-1][self.elem_key] = self.current['cves'][-1][self.elem_key] + s if self.elem_key in self.current['cves'][-1] else s
			self.elem_key = ''

	def endElement(self, tag):
		if tag == 'host':
			if self.current['exchange'] != None:
				self.hosts.append(self.current)
			self.current = {}
			self.table_tags = 0
			self.elem_key = ''

		elif tag == 'table':
			self.table_tags -= 1

	def parse(self, f):
		parser = xml.sax.make_parser()
		parser.setFeature(xml.sax.handler.feature_namespaces, False)
		parser.setContentHandler(self)
		parser.parse(f)
		return self.hosts

# Parse the xml
parser = Parser()
info = parser.parse(out_file)
os.remove(out_file)

# Summary of CVE -> Hosts
summary = {}
for host in info:
	for cve in host['cves']:
		summary[cve['id']] = summary[cve['id']] if cve['id'] in summary else []
		summary[cve['id']].append(host['address'])

print("\n\n")
print(summary)

# Create the markdown
with open(md_file, 'w') as f:
	f.write("# Scan of: %s\n\n" % (datetime.now().strftime("%Y-%m-%d_%H-%M")))
	f.write("This is an automated scan with the [MS-Exchange-Version-NSE](https://github.com/righel/ms-exchange-version-nse) nmap script.\n\n")
	f.write("The following command was used:\n\n```\n$ %s\n```\n\n" % (nmap_cmd))

	f.write("## Summary\n\n")
	f.write("| CVE | Hosts |\n|--|--|\n")
	for cve in summary:
		f.write(f"| [{cve}](https://vulners.com/cve/{cve}) | {', '.join(summary[cve])} |\n")
	f.write("\n")

	f.write("## Details\n\n")
	for host in info:
		f.write(f"### Scan for {host['address']}\n\n")
		f.write(f"* **ip:** {host['address']}\n")
		f.write(f"* **dns:** {host['name']}\n")
		f.write(f"* **product:** {host['exchange']['product']}\n")
		f.write(f"* **build:** {host['exchange']['build']}\n")
		f.write(f"* **release_date:** {host['exchange']['release_date']}\n")
		f.write("\n")

		for cve in host['cves']:
			f.write(f"#### {cve['id']} *({cve['cwe']})*\n\n")
			f.write(f"{cve['summary']}\n")
			f.write(f"*([Details: {cve['id']}](https://vulners.com/cve/{cve['id']}))*\n\n")
			f.write(f"* **cvss:** {cve['cvss']}\n")
			f.write(f"* *date:* {cve['cvss-time']}\n")
			f.write(f"* *update:* {cve['last-modified']}\n")
			f.write("\n")

		f.write("\n")

# Cleanup
md_files = []
for f in os.listdir('./scans/'):
	md_files.append(f)
md_files = sorted(md_files)

for f in md_files[:-max_reports]:
	os.remove('./scans/' + f)

exit(0)
