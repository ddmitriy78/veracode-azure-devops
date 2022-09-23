#from __future__ import annotations
from ast import keyword
from re import T
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

def write_csv_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".csv")
    file1 = open("output/" + filename + ".csv", 'w')
    file1.write(str(input)) # write to file
    file1.close()  

def process_veracode_findings(findings, scan_type, app_guid, app_name, flaw_url, app_metadata):
    #####################PROCESS FINDINGS######################
    count = 0
    output = []
    MitigationAction = {
        "Application Design":"APPDESIGN",
        "Network Environment": "NETENV",
        "OS Environment": "OSENV",
        "Request Risk Acceptance": "ACCEPTRISK",
        "(CyberOnly) Accept Risk": "ACCEPT"
    }

    # Look for security metadata to configure the workitems, data from security_metadata.json
    if "destination" in app_metadata.keys():  # set appropriate ADO organizaiton and project 
        destination = app_metadata["destination"]
    else:
        destination = None
    if "tags" in app_metadata.keys(): # set custom tags 
        tags = app_metadata["tags"]
    else:
        tags = None
    if findings:
        for finding in findings:
            first_found_date = pd.to_datetime(finding["finding"]["finding_status"]["first_found_date"])
            last_seen_date = pd.to_datetime(finding["finding"]["finding_status"]["last_seen_date"])
            finding_status = finding["finding"]["finding_status"]["status"]
            resolution = finding["finding"]["finding_status"]["resolution"]
            resolution_status = finding["finding"]["finding_status"]["resolution_status"]
            scan_type = finding["finding"]["scan_type"]
            # Define State of the work items based on the Veracode finding
            # FOUND THAT THIS CAN EFFECT CREATING AND UPDATEING WORK ITEMS IF BOARD IS NOT IN SYNC
            if finding["finding"]["finding_status"]["status"] == "CLOSED":
                bug_status = "Closed"
            # elif finding["finding"]["finding_status"]["resolution_status"] == "PROPOSED":
            #     bug_status = "Active"
            # elif finding["finding"]["finding_status"]["resolution_status"] == "REJECTED":
            #     bug_status = "Active"
            elif finding["finding"]["finding_status"]["status"] == "OPEN":
                bug_status = "New"
            # else:
            #     bug_status = "New"
            count += 1
            if scan_type == "STATIC":
                issueid = finding["finding"]["issue_id"]
                static_flow_info = vc_findings.get_static_flow_info(app_name, app_guid, issueid)
            else:
                static_flow_info = None
            if finding["finding"]["finding_details"]["severity"] >= 3 and cut_off_date.date() < last_seen_date.date():
                bug_status = "New"
                
                #Create bug from findings, processing formating
                bug = workitem.veracode_finding(finding, flaw_url, tags, bug_status) # NEED TO PASS TAGS 
                id = workitem.find_workitem(bug, destination)
                bug_last_seen_date = bug["Last Seen Date"]
                #c hecking if work item exists if does not exist creating work item
                if id["id"] is None:
                    print("found workitem:", id)
                    print("Creating bug: ", bug["Title"])
                    work_item = workitem.create_secbug(bug, destination, static_flow_info)  # Create workitems based on finding 
                else:
                    print("Work item already exists:", id)
                    work_item = json.loads(workitem.get_workitem(id, destination))
                    # Finding workitems that have mitigation submitted for OPEN findings: This steps applies to STATIC and SCA

                    # Work item State is Active: This is where we expecte MitigationAction to be set, but MitigationApproved is to not exisit
                    if ("Custom.MitigationAction" in work_item["fields"].keys()) and ("Custom.MitigationApproved" not in work_item["fields"].keys()):
                        if ((work_item["fields"]["System.State"] != "New") and (finding_status != "CLOSED") and (resolution_status != "PROPOSED")):
                            # Submit mitigation request in veracode if Mitigation action is
                            if (work_item["fields"]["Custom.MitigationAction"] == "Application Design"):
                                bug_status = work_item["fields"]["System.State"]
                                action = "APPDESIGN"
                                comment = "\rAutomation has taken and action on this flaw\r\nAction: " + action + " \r\nWork item change: " + work_item["fields"]["System.State"] + ": Name: " + bug["Title"] + "\r\n" + id["url"]                            
                                if scan_type == "STATIC":
                                    vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)
                                workitem.add_comment_secbug(id, comment, destination)
                            if ((work_item["fields"]["Custom.MitigationAction"] == "Network Environment")):
                                bug_status = work_item["fields"]["System.State"]
                                action = "NETENV"
                                comment = "\rAutomation has taken and action on this flaw\r\nAction: " + action + " \r\nWork item change: " + work_item["fields"]["System.State"] + ": Name: " + bug["Title"] + "\r\n" + id["url"]                            
                                if scan_type == "STATIC":
                                    vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)
                                workitem.add_comment_secbug(id, comment, destination)
                            if ((work_item["fields"]["Custom.MitigationAction"] == "OS Environment")):
                                bug_status = work_item["fields"]["System.State"]
                                action = "OSENV"
                                comment = "\rAutomation has taken and action on this flaw\r\nAction: " + action + " \r\nWork item change: " + work_item["fields"]["System.State"] + ": Name: " + bug["Title"] + "\r\n" + id["url"]                            
                                if scan_type == "STATIC":
                                    vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)
                                workitem.add_comment_secbug(id, comment, destination)
                            if ((work_item["fields"]["Custom.MitigationAction"] == "Request Risk Acceptance")):
                                bug_status = work_item["fields"]["System.State"]
                                action = "ACCEPTRISK"
                                comment = "\rAutomation has taken and action on this flaw\r\nAction: " + action + " \r\nWork item change: " + work_item["fields"]["System.State"] + ": Name: " + bug["Title"] + "\r\n" + id["url"]                            
                                if scan_type == "STATIC":
                                    vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)
                                workitem.add_comment_secbug(id, comment, destination)
                    if work_item["fields"].keys() >= {"Custom.MitigationApproved", "Custom.MitigationAction"}:
                        if work_item["fields"]["System.State"] != "New" and resolution_status == "PROPOSED":
                            if work_item["fields"]["Custom.MitigationApproved"] == "REJECTED":
                                bug_status = "New"
                                action = "REJECTED"
                                comment = "\rAutomation has taken and action on this flaw\r\nAction: " + action + " \r\nWork item change: " + work_item["fields"]["System.State"] + ": Name: " + bug["Title"] + "\r\n" + id["url"]                            
                                if scan_type == "STATIC":
                                    vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)
                                workitem.add_comment_secbug(id, comment, destination)
                            if work_item["fields"]["Custom.MitigationApproved"] == "ACCEPTED":
                                bug_status = "Closed"
                                action = "ACCEPTED"
                                comment = "\rAutomation has taken and action on this flaw\r\nAction: " + action + " \r\nWork item change: " + work_item["fields"]["System.State"] + ": Name: " + bug["Title"] + "\r\n" + id["url"]                            
                                if scan_type == "STATIC":
                                    vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)                         
                                workitem.add_comment_secbug(id, comment, destination)
                    # bug = workitem.veracode_finding(finding, flaw_url, tags, bug_status)
                    # workitem.update_secbug(id, work_item, bug, destination)   
                    if ((finding_status == "CLOSED") and (work_item["fields"]["System.State"] != "Closed")):  # close work item if finding in Veracode is closed
                        bug["Status"] = "Closed"
                        workitem.update_secbug(id, work_item, bug, destination)  
                        action = "COMMENT"
                        comment = "\r\nAction: CLOSED Work Item \r\nName: " + bug["Title"]
                        vc_annotations.vc_annotations(app_name, app_guid, issueid, comment, action)
                    elif bug["Resolutions_Status"] != work_item["fields"]["Custom.VC_Resolutions_Status"]:  # If Resulution Status doesn't match update the work item.
                        bug["Status"] = work_item["fields"]["System.State"] # Don't change work item state, update everything else
                        workitem.update_secbug(id, work_item, bug, destination)  

                output.append(work_item)

    else:

        next

    if output:
        filename = app_name + "_" + app_guid + "_" + scan_type
        write_json_file(output, filename)
        # data = pd.json_normalize(output)
        # write_csv_file(data.to_csv(), filename)
    
       

if __name__ == "__main__":

    # Open metadata config file 
    relative_dir = os.path.dirname(__file__)
    f = open("security_metadata.json", 'r')
    security_metadata = json.loads(f.read())

    # Get list of applications from Veracode
    app_list = vc_applist.app_list() 
    write_json_file(app_list, "app_list")

#########################   ######GET SCAN RESULTS#####################################
    y = 0
    while True:
        threads = []
        y += 1
        t = 0

        for app in app_list:
            flaw_url = "https://analysiscenter.veracode.com/auth/index.jsp#ReviewResultsFlaw:" + str(app["oid"]) + ":" + str(app["id"]) + "::"        
            app_name = (app["profile"]["name"])
            app_guid = (app["guid"])
            for x in range(20):
                if app_name in security_metadata.keys():
                    t += 1
                    app_metadata = security_metadata[app_name]
                    api_static = (static_scan, annotations_api, violates_policy_api)
                    api_sca = (sca_scan, cvss_gte, annotations_api)
                    findings_static = vc_findings.findings_api2(app_name, app_guid, api_static)
                    findings_sca = vc_findings.findings_api2(app_name, app_guid, api_sca)

            #####################PROCESS FINDINGS######################
                    thread1 = "t" + str(t) + "-" + str(y) + "-1"
                    thread2 = "t" + str(t) + "-" + str(y) + "-2"

                    thread1 = threading.Thread(target=process_veracode_findings, args=[findings_static, "STATIC", app_guid, app_name, flaw_url, app_metadata])
                    thread2 = threading.Thread(target=process_veracode_findings, args=[findings_sca, "SCA", app_guid, app_name, flaw_url, app_metadata])
                    thread1.start()
                    thread2.start()
                    threads.append(thread1)
                    threads.append(thread2)
                break
        # for thread in threads:
        #     thread.join()

 


