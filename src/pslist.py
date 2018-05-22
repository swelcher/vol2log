import json
import urllib.request
from compare import enumerate_dict
from compare import enumerate_dict_ppid


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
            elif len(explorer_pid) == len(winlogon_pid):
                dictionary["PotentiallyMaliciousProcess"] = "True"
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









































