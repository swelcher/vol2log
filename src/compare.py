# Purpose of these functions is to enumerate the defined dictionaries to return the values at the specific locations.
def enumerate_dict(analyze_dictionary):
	for key, value in analyze_dictionary.items():
		if key == "Name":
			return value


def enumerate_dict_ppid(analyze_dictionary):
	for key, value in analyze_dictionary.items():
		if key.upper() == "PPID":
			return value

def enumerate_dict_pid(analyze_dictionary):
	for key, value in analyze_dictionary.items():
		if key.upper() == "PID":
			return value

def enumerate_dict_path(analyze_dictionary):
        for key, value in analyze_dictionary.items():
                if key == "Path":
                        return value

def enumerate_image(analyze_dictionary, pid):
	for key, value in analyze_dictionary.items():
		if key == pid:
			return value
