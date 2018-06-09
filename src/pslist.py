import json
import urllib.request
from src.compare import enumerate_dict
from src.compare import enumerate_dict_ppid


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
	
	typical_services = ["winlogon.exe", "wininit.exe", "services.exe", "explorer.exe", "lsm.exe", "csrss.exe", "lsass.exe", "smss.exe", "rdpclip.exe", "System", "iexplore.exe", "dllhost.exe", "rundll32.exe", "WmiPrvSE.exe", "conhost.exe", "regsvr32.exe", "dwm.exe", "WUDFHost.exe", "LogonUI.exe", "mobsync.exe", "wmdcBase.exe.exe", "unsecapp.exe", "audiodg.exe", "chrome.exe", "firefox.exe", "MicrosoftEdge.exe", "audiodg.exe", "Calculator.exe", "OUTLOOK.EXE", "POWERPNT.EXE", "EXCEL.EXE", "MSACCESS.EXE", "onenoteim.exe", "WINWORD.EXE", "OfficeClickToRun.exe", "Taskmgr.exe", "mmc.exe", "7zFM.exe", "cmd.exe", "powershell.exe", "powershell_ise.exe", "notepad++.exe", "OneDrive.exe", "RuntimeBroker.exe", "SearchUI.exe", "audiodg.exe", "SearchIndexer.exe", "sppsvc.exe", "WmiApSrv.exe", "wifitask.exe", "mobsync.exe", "ngen.exe", "AcroRd32.exe", "AcroCEF.exe", "Creative Cloud.exe", "EMET_Service.exe", "slack.exe", "System Idle Process", "System interrupts", "unsecapp.exe"] 

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

			if process_name in typical_process:
				dictionary["TypicalProcess"] = "True"
			elif:
				dictionary["TypicalProcess"] = "False"
		    # If enabling this check below, it is possible for false positives, due to the initial initialization of
		    # csrss and exiting of the first process.
		    # elif process_name == "csrss.exe" and (ppid_name not in smss_pid or len(csrss_pid) > 1):
		    #    dictionary["PotentiallyMaliciousProcess"] = "True"

		    # Creation of required field for Graylog
			dictionary["short_message"] = "true"
		    # Creation of analyzed host field
			dictionary["host"] = str(vol_host)
		    # Creation of plugin field
			dictionary["plugin"] = "pslist"
		    # Creation of post to Graylog
			response = urllib.request.urlopen(url, data=bytes(json.dumps(dictionary), encoding="utf-8"))
		    # Post to Graylog.
			print(response.read())









































