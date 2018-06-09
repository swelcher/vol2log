import json
import argparse
from src.pslist import pslist_threat
from src.getsids import getsids
from src.jsonpost import jsonpost
from src.generic import generic_analysis
from src.dlllist import dlllist


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
			    help="Enter Volatility Plugin", required=True, choices=["pslist", "netscan", "dlllist", "getsids","userassist"])
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
	elif plugin == "getsids":
		getsids(json_file, vol_host, url)	
	elif plugin == "dlllist":
		dlllist(json_file, vol_host, url)
	else:
		generic_analysis(json_file, vol_host, plugin, url)	
	
# Error Handling

except Exception as e:
	message = str(e)
	print(message)
