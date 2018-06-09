# Purpose of these functions is to enumerate the defined dictionaries to return the values at the specific locations.
def enumerate_dict(analyze_dictionary):
	for key, value in analyze_dictionary.items():
		if key == "Name":
			return value


def enumerate_dict_ppid(analyze_dictionary):
	for key, value in analyze_dictionary.items():
		if key == "PPID":
			return value

def enumerate_dict_pid(analyze_dictionary):
	for key, value in analyze_dictionary.items():
		if key == "PID":
			return value

def enumerate_dict_name(analyze_dictionary):
        for key, value in analyze_dictionary.items():
                if key == "Name":
                        return value
