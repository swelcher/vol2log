import json
from src.jsonpost import jsonpost


def generic_analysis(json_file, vol_host, plugin, url):

	with open(json_file) as file:
		volFile = json.load(file)
		for row in volFile['rows']:
			dictionary = {}
			for key, value in zip(volFile['columns'], row):
				dictionary[key] = value
			dictionary["plugin"] = str(plugin)
			jsonpost(vol_host, url, dictionary)

