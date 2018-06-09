from src.jsonpost import jsonpost
from src.compare import enumerate_dict_pid
from src.compare import enumerate_dict_name


def dlllist(json_file, vol_host, url):

        process_id = []
	

	# Initial Analysis of JSON File
        with open(json_file) as file:
                vol_file = json.load(file)
                for row in vol_file['rows']:
                        analyzedictionary = {}
                        for key, value in zip(vol_file['columns'], row):
                                analyzedictionary[key] = value
            # Call to enumerate_dict Function. Located in src.
                        process_name = enumerate_dict(analyzedictionary).lower()

        with open(json_file) as file:
                        vol_file = json.load(file)
                        for row in vol_file['rows']:
                                dictionary = {}
                                for key, value in zip(vol_file['columns'], row):
                                        dictionary[key] = value

                                pid = enumerate_dict_pid(dictionary)
                                if pid not in process_id:
					process_id.append(pid)
					dictionary["Executable"] = "True"
					dictionary["plugin"] = "dlllist"
					jsonpost(vol_host, url, dictionary)

				else:
					executable_name = enumerate_dict_name(dictionary)	
					dictionary["ParentExecutable"] = executable_name
					dictionary["plugin"] = "dlllist"
					jsonpost(vol_host, url, dictionary)
