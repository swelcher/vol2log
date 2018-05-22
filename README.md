# vol2log

## Summary

This utility built upon Python 3.6 is to assist with shipping a Volatility JSON file into Graylog with the appropriate formatting easily. I was unaware of a way to easily ship the JSON file from Volatility's unified-output plugin so I created a small utility which will format, add additional needed fields to the post, and send a post request to a specified Graylog instance.

----------------------------------------------------------------------------------------------------------------------------------------

## Usage

    python vol2log.py -host 192.168.119.133 -port 12201 -jsonFile "C:\Python\Data\Volatility JSON Files\netscan.json" -plugin netscan -volHost infectedhost

----------------------------------------------------------------------------------------------------------------------------------------
## Required Switches

  -host \<IP address of remote Graylog Instance.\>
  
  -port \<Port number of listening HTTP Gelf input in Graylog.\>
  
  -plugin \<Name of volatility plugin that was used for JSON file.\>
  
  -volHost \<Name or IP address of the src of the analyzed memory dump.\>
  
  -jsonFile \<File path to jsonFile\.>
  
  ----------------------------------------------------------------------------------------------------------------------------------------
  
## Future Features

  -Require naming convention of file name of host.plugin.json to auto-populate plugin and make volHost and plugin optional switches.
  
  -Be able to handle large quantities of JSON files.
  
  -Create a list of known issues with certain plugins as not all plugins produce data that is usable in this format.
    i.e malfind's output
