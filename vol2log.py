import json
import urllib.request
import argparse
from src.pslist import pslist_threat
parser = argparse.ArgumentParser()
try:
	# Generate Graylog Host Commandline Parameter
	parser.add_argument("-host", action='store', dest='ip_addr',
			    help="Set Graylog IP address", required=True)
	# Generate Graylog Port Commandline Parameter
	parser.add_argument("-port", action='store', dest='port',
			    help="Enter Graylog Input port", required=True)
	# Generate JSON File Commandline Parameter
	parser.add_argument("-file", action='store', dest='json_file',
			    help="Enter JSON file to send to Graylog", required=True)
	# Generate Volatility Plugin Commandline Parameter
	parser.add_argument("-plugin", action='store', dest='plugin',
			    help="Enter Volatility Plugin", required=True, choices=["pslist", "netscan", "dlllist"])
	# Generate Analyzed Host Commandline Parameter
	parser.add_argument("-volhost", action='store', dest='vol_host',
			    help="Enter Memory dump Source Name or IP", required=True)
	# Redefine arguments for a cleaner approach
	arguments = parser.parse_args()
	ip_addr = arguments.ip_addr
	port = arguments.port
	json_file = arguments.json_file
	plugin = arguments.plugin
	vol_host = arguments.vol_host
	# Define URL for posting JSON to Graylog
	url = "http://" + str(ip_addr) + ":" + str(port) + "/gelf"
	# Analysis of plugin parameter
	if plugin == "pslist":
		pslist_threat(json_file, vol_host, url)
	else:
		with open(json_file) as file:
			volFile = json.load(file)
			for row in volFile['rows']:
				dictionary = {}
				for key, value in zip(volFile['columns'], row):
					dictionary[key] = value
				print(dictionary)
				dictionary["short_message"] = "true"
				dictionary["host"] = str(vol_host)
				dictionary["plugin"] = str(plugin)
				response = urllib.request.urlopen(url, data=bytes(json.dumps(dictionary), encoding="utf-8"))
				print(response.read())
# Error Handling

except Exception as e:
	message = str(e)
	print(message)
















































