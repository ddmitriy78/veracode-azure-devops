from operator import eq
import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json
from json import JSONDecodeError


import vc_applist
import logger

api_base = "https://api.veracode.com/appsec/"
start_date = datetime.datetime.now() - datetime.timedelta(30)

def get_page_count(app_name, api):
    try:
        response = requests.get("https://api.veracode.com/appsec/v1/applications/?page=0&size=500", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
    except requests.RequestException as e:
        logger.logger_event("vc_findings.py", "get_page_count", ("Whoops got an error!"))
        logger.logger_event("vc_findings.py", "get_page_count", (e))
        sys.exit(1)   

    if response.ok:
        data = response.json()
        
        for app in data["_embedded"]["applications"]:
            last_completed_scan_date = pd.to_datetime(app["last_completed_scan_date"])
            if app_name == app["profile"]["name"]:
                app_guid = app["guid"]    
            else:
                app_name == app["profile"]["name"]
                next 
    
    try: 
        response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=100&page=0" + "&" + api, auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
    except requests.RequestException as e:
        logger.logger_event("vc_findings.py", "get_page_count", ("Whoops got an error!"))
        logger.logger_event("vc_findings.py", "get_page_count", (e))
        sys.exit(1)
    if response.ok:
        data = response.json()
        total_pages = int(data["page"]["total_pages"])
        total_elements = int(data["page"]["total_elements"])
        list = {"app_name": app_name, "app_guid": app_guid, "total_elements": total_elements, "total_pages": total_pages}
    else:
        logger.logger_event("vc_findings.py", "get_page_count", (response.status_code)) 
    return list    

def findings_api2(app_name, app_guid, api):     # api should be a list

    uri = "&".join(api)
    try: 
        response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=0" + "&" + str(uri), auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
        logger.logger_event("vc_findings.py", "findings_api2", ("api call", "https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=0" + "&" + str(uri)))
    except requests.RequestException as e:
        logger.logger_event("vc_findings.py", "findings_api2", ("Whoops got an error!"))
        logger.logger_event("vc_findings.py", "findings_api2", (e))
        sys.exit(1)
    if response.ok:
        output = []
        page_number = 0
        findings_count = 0
        data = response.json()
        total_pages = int(data["page"]["total_pages"])
        total_elements = int(data["page"]["total_elements"])
        #for x in range(1): # FOR TESTING limiting number of pages to 1
        for x in range(total_pages):
            logger.logger_event("vc_findings.py", "findings_api2", ("getting results for:", app_name))
            logger.logger_event("vc_findings.py", "findings_api2", ("Page", x, "out of", total_pages))
            try:

                response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=" + str(x) + "&" + str(uri), auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
                logger.logger_event("vc_findings.py", "findings_api2", ("api call", "https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings?size=500&page=" + str(x) + "&" + str(uri)))
            except requests.RequestException as e:
                logger.logger_event("vc_findings.py", "findings_api2", ("Whoops got an error!"))
                logger.logger_event("vc_findings.py", "findings_api2", (e))
                #sys.exit(1)
            try:
                resp_dict = response.json()
                if response.json()["page"]["total_elements"] > 0:
                    data = response.json()
                    total_pages = int(data["page"]["total_pages"])
                    page_number += 1
                    findings = data["_embedded"]["findings"]
                    for finding in findings:
                        findings_count += 1
                        output.append({"app_name": app_name, "findings_count": findings_count, "finding": finding})
            except JSONDecodeError:
                logger.logger_event("vc_findings.py", "findings_api2", ("Error response could not be searialzed"))
        else:
            logger.logger_event("vc_findings.py", "findings_api2", (response.status_code)) 
    else:
        logger.logger_event("vc_findings.py", "findings_api2", (response.status_code) )
        output = None

    return output  

def get_static_flow_info(app_name, app_guid, issueid):     # api should be a list

    try: 
        response = requests.get("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings/" + str(issueid) + "/static_flaw_info", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
        logger.logger_event("vc_findings.py", "get_static_flow_info", ("api call", "https://api.veracode.com/appsec/v2/applications/" + app_guid + "/findings/" + str(issueid) + "/static_flaw_info"))
    except requests.RequestException as e:
        logger.logger_event("vc_findings.py", "get_static_flow_info", ("Whoops got an error!"))
        logger.logger_event("vc_findings.py", "get_static_flow_info", (e))
    if response.ok:
        try:
            finding = response.json()
            if "issue_summary" in finding:
                output = finding
        except JSONDecodeError:
            output = None
            logger.logger_event("vc_findings.py", "get_static_flow_info", ("Error response could not be searialzed"))
    else:
        logger.logger_event("vc_findings.py", "get_static_flow_info", (response.status_code))
        logger.logger_event("vc_findings.py", "get_static_flow_info", ("API call failed"))
        output = None

    return output  

