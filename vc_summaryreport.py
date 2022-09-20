import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json


api_base = "https://api.veracode.com/appsec/"
api_ver1 = "v1"
api_ver2 = "v2"
headers = {"User-Agent": "Python HMAC Example"}
start_date = datetime.datetime.now() - datetime.timedelta(30)
app_name = "Dayforce HCM Master"

def report(app_guid):
 
    try: 
        response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/summary_report", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        output = response.json()
    else:
        output = response.status_code
    return output
         


