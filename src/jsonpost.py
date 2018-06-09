import json
import urllib.request


def jsonpost(vol_host, url, dictionary):
	# Creation of required field for Graylog
	dictionary["short_message"] = "true"
	# Creation of analyzed host field
	dictionary["host"] = str(vol_host)
	print(dictionary)
	# Creation of post to Graylog
	response = urllib.request.urlopen(url, data=bytes(json.dumps(dictionary), encoding="utf-8"))
	# Post to Graylog.
	print(response.read())
