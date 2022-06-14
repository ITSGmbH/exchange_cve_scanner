from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime
import os, re, markdown

ip = '0.0.0.0'
port = 8080

class MdServer(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-Type", "text/html")
		self.end_headers()

		md = ''
		if self.path == '/':
			md = "# Scans\n\n"
			for f in os.listdir('./scans/'):
				d = datetime.strptime(f[:-3], '%Y-%m-%d_%H-%M')
				md += "* [%s](/%s)\n" % (d.strftime('%Y-%m-%d %H:%M'), f)

		elif self.path[1:4] == 'raw':
			md_file = re.sub('[^0-9_-]+', '', self.path) + '.md'
			with open('scans/' + md_file, 'r') as f:
				self.wfile.write(bytes("".join(f.readlines()), 'utf-8'))

		else:
			md_file = re.sub('[^0-9_-]+', '', self.path) + '.md'
			with open('scans/' + md_file, 'r') as f:
				md = '<p><a href="/">back</a>&nbsp;|&nbsp;<a href="raw%s">download</a></p>' % (self.path)
				md += "".join(f.readlines())

		if len(md) > 0:
			html = markdown.markdown(md, extensions=['tables'])
			header = """<!DOCTYPE html>\n<html><head>
			<style>
			html,body { margin:0;padding:10px;height:100%;font-family:Arial,helvetica,sans-serif; }
			code { display:block;padding:5px;margin:10px;background:#ededed;border:1px solid #999;color:#555;box-shadow:2px 3px 10px 1px rgba(200,200,200,1); }
			td,th { padding:8px 16px 8px 8px;border:1px solid #0078d4; }
			thead { font-weight:bold;color:#eee; background:#004e8c; }
			table { border-collapse:collapse; }
			h2 { margin-top:50px; }
			h3 { border-bottom:1px solid #0078d4;background:#004e8c;color:#eee;padding:8px 16px 8px 8px; }
			h4 { border-bottom:1px solid #0078d4; }
			</style>
			</head><body>"""
			footer = "</body></html>"
			self.wfile.write(bytes(header, 'utf-8'))
			self.wfile.write(bytes(html, 'utf-8'))
			self.wfile.write(bytes(footer, 'utf-8'))

if __name__ == "__main__":
	server = HTTPServer((ip, port), MdServer)
	print("Server started http://%s:%s" % (ip, port))
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass
	server.server_close()
	print("Server stopped.")

