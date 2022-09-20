#from __future__ import annotations
from ast import keyword
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
import vc_annotations

first_detection = datetime.datetime.now() - datetime.timedelta(30)
due_date = datetime.datetime.now() + datetime.timedelta(30)
cut_off_date = datetime.datetime.now() - datetime.timedelta(365)

flaw_url = "https://analysiscenter.veracode.com/auth/index.jsp#ReviewResultsFlaw:"

##### Examples of findings API ######
new_findings = "new=true"
sca_scan = "scan_type=SCA"
cvss_gte = "cvss_gte=5"
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

def normalize_json(data: dict) -> dict:
  
    new_data = dict()
    for key, value in data.items():
        if not isinstance(value, dict):
            new_data[key] = value
        else:
            for k, v in value.items():
                new_data[key + "_" + k] = v
      
    return new_data

def write_csv_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".csv")
    file1 = open("output/" + filename + ".csv", 'w')
    file1.write(str(input)) # write to file
    file1.close()  
    
def get_sbom(app_name, app_guid):

    try: 
        response = requests.get("https://api.veracode.com/srcclr/sbom/v1/targets/" + app_guid + "/cyclonedx?type=application", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = False)
        print("api call", "https://api.veracode.com/srcclr/sbom/v1/targets/" + app_guid + "/cyclonedx?type=application")
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        try:
            output = response.json()
            if "bomFormat" in output.keys():
                print("got sbom out")
        except JSONDecodeError:
            output = None
            print("Error response could not be searialzed")      
    else:
        print(response.status_code)   
        print("API call failed")
        output = None

    return output     

if __name__ == "__main__":

    # Get list of applications from Veracode
    app_list = vc_applist.app_list() 
    write_json_file(app_list, "app_list")

    # Open metadata config file 
    f = open("/Users/p129181/Code/veracode/2test_security_metadata.json", 'r')
    security_metadata = json.loads(f.read())
    print(security_metadata)


###############################GET SCAN RESULTS#####################################
    for app in app_list:
        flaw_url = "https://analysiscenter.veracode.com/auth/index.jsp#ReviewResultsFlaw:" + str(app["oid"]) + ":" + str(app["id"]) + "::"

        app_name = (app["profile"]["name"])
        app_guid = (app["guid"])
        if app_name in security_metadata.keys():
            app_metadata = security_metadata[app_name]
            sbom = get_sbom(app_name, app_guid)
            print(sbom.keys())
            print(sbom["components"][0].keys())
            print(sbom["vulnerabilities"][0].keys())
            print(sbom["dependencies"][0].keys())
            count = 0
            for component in sbom["components"]:
                count += 1
                print()
                







 


