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

def get_page_count():
 
    try: 
        response = requests.get("https://api.veracode.com/appsec/v1/applications/?page=0&size=500", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        data = response.json()
        total_pages = int(data["page"]["total_pages"])
        total_elements = int(data["page"]["total_elements"])
        list = {"total_elements": total_elements, "total_pages": total_pages}
    else:
        print(response.status_code)   
    return list

def app_list(): 
    total_pages = get_page_count()["total_pages"]
    for page in range(total_pages):
        try: 
            response = requests.get("https://api.veracode.com/appsec/v1/applications/?page="+str(page)+"&size=500", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
        except requests.RequestException as e:
            print("Whoops!")
            print(e)
            sys.exit(1)
        if response.ok:
            data = response.json()
    return data["_embedded"]["applications"]

def compliance(app_list):
    print(json.dumps(app_list,indent=4))
    output = []
    count = 0
    for app in app_list:
        count += 1
        last_completed_scan_date = pd.to_datetime(app["last_completed_scan_date"])
        app_guid = app["guid"]
        if app["profile"]["custom_fields"] is None: # checking custome metadata fields, need to expand this to specific fields like security champion
            custom_fields = "FAIL"
        else:
            custom_fields = "PASS"
        if last_completed_scan_date is not None:
            LastCompleteScan = str(last_completed_scan_date.date())
            if start_date.date() > last_completed_scan_date.date(): # checking if the scan been completed in last 30 days
                scan_frequency = "FAIL"
            else:
                scan_frequency = "PASS"
        else:
            LastCompleteScan = "NONE"
            scan_frequency = "FAIL"

        list = ({"Count": str(count), "AppName": app["profile"]["name"], "AppID": app_guid, "Compliance": {"LastCompleteScan": LastCompleteScan, "Scan_Frequency": scan_frequency, "policy_compliance_status": app["profile"]["policies"][0]["policy_compliance_status"], "custom_fields": custom_fields}})
        output.append(list)
            
    return output            


