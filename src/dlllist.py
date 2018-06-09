import json
from src.jsonpost import jsonpost
from src.compare import enumerate_dict_pid
from src.compare import enumerate_dict_path
from src.compare import enumerate_image


def dlllist(json_file, vol_host, url):

	process_id_check = []
	process_id = {}

	with open(json_file) as file:
			vol_file = json.load(file)
			for row in vol_file['rows']:
				dictionary = {}
				for key, value in zip(vol_file['columns'], row):
					dictionary[key] = value

				pid = enumerate_dict_pid(dictionary)
				if pid not in process_id_check:
					image = enumerate_dict_path(dictionary)		
					process_id[pid] = image
					process_id_check.append(pid)
					dictionary["Image"] = "True"
					dictionary["plugin"] = "dlllist"
					jsonpost(vol_host, url, dictionary)

				else:
					image = enumerate_image(process_id, pid)	
					dictionary["ParentImage"] = image
					dictionary["plugin"] = "dlllist"
					jsonpost(vol_host, url, dictionary)
