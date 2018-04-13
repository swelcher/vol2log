# vol2log

**This utility is to assist with shipping a JSON file into Graylog with the appropriate formatting. Here is a sample usage:**

    python vol2log.py -host 192.168.119.133 -port 12201 -jsonFile "C:\Python\Data\Volatility JSON Files\netscan.json" -plugin netscan -volHost infectedhost

----------------------------------------------------------------------------------------------------------------------------------------
**There are 5 required switches with are:**

  -host \<IP address of remote Graylog Instance.\>
  
  -port \<Port number of listening HTTP Gelf input in Graylog.\>
  
  -plugin \<Name of volatility plugin that was used for JSON file.\>
  
  -volHost \<Name or IP address of the src of the analyzed memory dump.\>
  
  -jsonFile \<File path to jsonFile\.>
  
  ----------------------------------------------------------------------------------------------------------------------------------------
  
**These are additional features that I intend on implementing in the future and will add those as issues as well**

  -Require naming convention of file name of host.plugin.json to auto-populate plugin and make volHost and plugin optional switches.
  
  -Be able to handle large quantities of JSON files.
  
  -Create a list of known issues with certain plugins as not all plugins produce data that is usable in this format.
    i.e malfind's output
  
