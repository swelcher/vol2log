import json
from src.compare import enumerate_dict
from src.compare import enumerate_dict_ppid
from src.jsonpost import jsonpost


def pslist_threat(json_file, vol_host, url):

	# List Definitions
	services_pid = []
	system_pid = []
	smss_pid = []
	lsass_pid = []
	wininit_pid = []
	svchost_pid = []
	dllhost_pid = []
	lsm_pid = []
	winlogon_pid = []
	explorer_pid = []
	csrss_pid = []
	
	typical_services = ["winlogon.exe", "wininit.exe", "services.exe", "explorer.exe", "lsm.exe", "csrss.exe", "lsass.exe", "smss.exe", "rdpclip.exe", "system", "iexplore.exe", "dllhost.exe", "rundll32.exe", "wmiprvse.exe", "conhost.exe", "regsvr32.exe", "dwm.exe", "wudfhost.exe", "logonui.exe", "mobsync.exe", "wmdcbase.exe.exe", "unsecapp.exe", "audiodg.exe", "chrome.exe", "firefox.exe", "microsoftedge.exe", "audiodg.exe", "calculator.exe", "outlook.exe", "powerpnt.exe", "excel.exe", "msaccess.exe", "onenoteim.exe", "winword.exe", "officeclicktorun.exe", "taskmgr.exe", "mmc.exe", "7zfm.exe", "cmd.exe", "powershell.exe", "powershell_ise.exe", "notepad++.exe", "onedrive.exe", "runtimebroker.exe", "searchui.exe", "audiodg.exe", "searchindexer.exe", "sppsvc.exe", "wmiApsrv.exe", "wifitask.exe", "mobsync.exe", "ngen.exe", "acrord32.exe", "acrocef.exe", "creative cloud.exe", "emet_service.exe", "slack.exe", "system idle process", "system interrupts", "unsecapp.exe", "svchost.exe"] 

	# Initial Analysis of JSON File
	with open(json_file) as file:
		vol_file = json.load(file)
		for row in vol_file['rows']:
			analyzedictionary = {}
			for key, value in zip(vol_file['columns'], row):
				analyzedictionary[key] = value
            # Call to enumerate_dict Function. Located in src.
			process_name = enumerate_dict(analyzedictionary).lower()
			if process_name == "services.exe":
				services_pid.append(analyzedictionary["PID"])
			elif process_name == "system":
				system_pid.append(analyzedictionary["PID"])
			elif process_name == "smss.exe":
				smss_pid.append(analyzedictionary["PID"])
			elif process_name == "lsass.exe":
				lsass_pid.append(analyzedictionary["PID"])
			elif process_name == "wininit.exe":
				wininit_pid.append(analyzedictionary["PID"])
			elif process_name == "svchost.exe":
				svchost_pid.append(analyzedictionary["PID"])
			elif process_name == "dllhost.exe":
				dllhost_pid.append(analyzedictionary["PID"])
			elif process_name == "lsm.exe":
				lsm_pid.append(analyzedictionary["PID"])
			elif process_name == "winlogon.exe":
				winlogon_pid.append(analyzedictionary["PID"])
			elif process_name == "explorer.exe":
				explorer_pid.append(analyzedictionary["PID"])
			elif process_name == "csrss.exe":
				csrss_pid.append(analyzedictionary["PID"])

    # Creation of Malicious Field, and checks of lsass, wininit, svchost, services, lsm, csrss, smss, and system.
	with open(json_file) as file:
		vol_file = json.load(file)
		for row in vol_file['rows']:
			dictionary = {}
			for key, value in zip(vol_file['columns'], row):
				dictionary[key] = value
			process_name = enumerate_dict(dictionary).lower()
			ppid_name = enumerate_dict_ppid(dictionary)
			if process_name == "lsass.exe" and (ppid_name not in wininit_pid or len(lsass_pid) > 1):
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "wininit.exe" and (ppid_name not in wininit_pid or len(wininit_pid) > 1):
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "svchost.exe" and (ppid_name not in services_pid):
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "services.exe" and (ppid_name not in wininit_pid):
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "lsm.exe" and (ppid_name not in wininit_pid or len(lsm_pid) > 1):
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "smss.exe" and (ppid_name not in system_pid or len(smss_pid) > 1):
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "system" and len(system_pid) > 1:
				dictionary["PotentiallyMaliciousProcess"] = "True"
			elif process_name == "winlogon.exe" and len(explorer_pid) != len(winlogon_pid):
				dictionary["PotentiallyMaliciousProcess"] = "True"

			if process_name.lower() in typical_services:
				dictionary["TypicalServices"] = "True"
			else:
				dictionary["TypicalServices"] = "False"
		    # If enabling this check below, it is possible for false positives, due to the initial initialization of
		    # csrss and exiting of the first process.
		    # elif process_name == "csrss.exe" and (ppid_name not in smss_pid or len(csrss_pid) > 1):
		    #    dictionary["PotentiallyMaliciousProcess"] = "True"

			dictionary["plugin"] = "pslist"
			print(dictionary)
			jsonpost(vol_host, url, dictionary)	








































