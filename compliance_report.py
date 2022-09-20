#from __future__ import annotations
import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json
import os
import csv
import time
from json2table import convert
import threading
from json import JSONDecodeError

# Import local file
import vc_applist
import vc_findings
import vc_summaryreport
import workitem

first_detection = datetime.datetime.now() - datetime.timedelta(30)
due_date = datetime.datetime.now() + datetime.timedelta(30)
cut_off_date = datetime.datetime.now() - datetime.timedelta(365)

##### Examples of findings API ######
new_findings = "new=true"
sca_scan = "scan_type=SCA"
cvss_gte6 = "cvss_gte=6"
static_scan = "scan_type=STATIC"
violates_policy_api = "violates_policy=TRUE"
annotations_api = "include_annot=TRUE"
severity_gte4 = "severity_gte=4"
severity_gte3 = "severity_gte=3"
application_name = ""


def application_compliance():
    output = []
    app_list = vc_applist.app_list() # Get list of applications from Veracode
    for app in vc_applist.compliance(app_list):
        # print(json.dumps(app, indent=4))
        output.append(app)
    return output

def write_json_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".json")
    file1 = open("output/" + filename + ".json", 'w')
    file1.write(str(json.dumps(input, indent=4))) # write to file
    file1.close()  

    return output

def write_csv_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".csv")
    file1 = open("output/" + filename + ".csv", 'w')
    file1.write(str(input)) # write to file
    file1.close()  


if __name__ == "__main__":

    # Open metadata config file 
    f = open("security_metadata.json", 'r')
    vc_metadata = json.loads(f.read())
    print(vc_metadata.keys())

    # Get list of applications from Veracode
    app_list = vc_applist.app_list() 
    write_json_file(app_list, "app_list")

    #Create custom compliance report
    compliance = vc_applist.compliance(app_list)
    data = pd.json_normalize(compliance)
    write_csv_file(data.to_csv(), "compliance")  


