import json
import urllib.request
import argparse
parser = argparse.ArgumentParser()

try:
        parser.add_argument("-host", action='store', dest='ipAddr',
                            help="Set Graylog IP address", required=True)
        parser.add_argument("-port", action='store', dest='port',
                            help="Enter Graylog Input port", required=True)
        parser.add_argument("-jsonFile", action='store', dest='jsonFile',
                            help="Enter JSON file to send to Graylog", required=True)
        parser.add_argument("-plugin", action='store', dest='plugin',
                            help="Enter Volatility Plugin", required=True)
        parser.add_argument("-volHost", action='store', dest='volHost',
                            help="Enter Memory dump Source Name or IP", required=True)
        arguments = parser.parse_args()
        ipAddr = arguments.ipAddr
        port = arguments.port
        jsonFile = arguments.jsonFile
        plugin = arguments.plugin
        volHost = arguments.volHost

        url = "http://" + str(ipAddr) + ":" + str(port) + "/gelf"
        with open(jsonFile) as file:
            volFile = json.load(file)
            for row in volFile['rows']:
                dictionary = {}
                for key, value in zip(volFile['columns'], row):
                    dictionary[key] = value
                print(dictionary)
                dictionary["short_message"] = "true"
                dictionary["host"] = str(volHost)
                dictionary["plugin"] = str(plugin)
                response = urllib.request.urlopen(url, data = bytes(json.dumps(dictionary), encoding="utf-8"))
                print(response.read())
except Exception as e:
    message = str(e)
    print(message)
