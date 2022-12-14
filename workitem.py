import os
import requests
import json
import pprint
import datetime
import logging
import datetime
from json2table import convert
import time
import pandas as pd
from json import JSONDecodeError

import logger

x = datetime.datetime.now()

# Get Azure DevOps PAT from ~/.automation/mypat
home_directory = os.path.expanduser( '~' ) 
f = open(home_directory + "/.automation/mypat", 'r')
string = f.read()
string = string.strip('\n')
AZURE_DEVOPS_PAT = string

def get_mypat():
    # Get Azure DevOps PAT from ~/.automation/mypat
    home_directory = os.path.expanduser( '~' ) 
    f = open(home_directory + "/.automation/mypat", 'r')
    AZURE_DEVOPS_PAT = f.read()
    return AZURE_DEVOPS_PAT

# This function expects a bug processed by veracode_findings function
def find_workitem(bug, destination):
    title = bug["Title"]
    logger.logger_event("workitem.py", "find_workitem", ("find_workitem", title))
    if destination:
        ado_org = destination["ado_org"]
        ado_project = destination["ado_project"]
        url = "https://dev.azure.com/" + ado_org + "/" + ado_project +"/_apis/wit/wiql?api-version=6.1-preview.2"
    else:
        url = "https://dev.azure.com/CompanyCybersecurity/VM2/_apis/wit/wiql?api-version=6.1-preview.2"
    data = {
    "query": str("Select [System.Id], [System.Title], [System.State] From WorkItems Where [System.Title] = '" + title + "'")
    }
    # print(json.dumps(data, indent=4))
    try:
        r = requests.post(url, json=data, 
            headers={'Content-Type': 'application/json'},
            auth=('', AZURE_DEVOPS_PAT))
    except requests.RequestException as e:
        logger.logger_event("workitem.py", "find_workitem", ("Whoops, got an error!"))
        logger.logger_event("workitem.py", "find_workitem", (e))
    #print(json.dumps(r.json(), indent=4))
    try:
        resp_dict = r.json()
        if len(r.json()["workItems"])>=1:
            workitemid = r.json()["workItems"][0]["id"]
            workitemurl = r.json()["workItems"][0]["url"]
        else:
            workitemid = None
            workitemurl = None
        id = {
            "id": workitemid,
            "url": workitemurl
        }
    except JSONDecodeError:
        logger.logger_event("workitem.py", "find_workitem", ("Error response could not be searialzed")) 
    return id

# This function expects dict with id["id"]
def get_workitem(id, destination):
    logger.logger_event("workitem.py", "find_workitem", ("get_workitem", id))
    workitemid = str(id["id"])
    if destination:
        ado_org = destination["ado_org"]
        ado_project = destination["ado_project"]

        url = "https://dev.azure.com/" + ado_org + "/" + ado_project +"/_apis/wit/workitems/" + workitemid + "?api-version=2.0"
    else:
        url = "https://dev.azure.com/CompanyCybersecurity/VM2/_apis/wit/workitems/" + workitemid + "?api-version=2.0"
    try:
        r = requests.get(url, 
        headers={'Content-Type': 'application/json-patch+json'},
        auth=('', AZURE_DEVOPS_PAT))
    except requests.RequestException as e:
        logger.logger_event("workitem.py", "get_workitem", ("Whoops, got an error!"))
        logger.logger_event("workitem.py", "get_workitem", (e))

    return json.dumps(r.json(), indent=4)

# Process veracode finding into a bug for work item
def veracode_finding(finding, flaw_url, tags, bug_status):

    #Set Due Date
    first_detection = datetime.datetime.now() - datetime.timedelta(30)
    due_date = datetime.datetime.now() + datetime.timedelta(30)
    first_found_date = pd.to_datetime(finding["finding"]["finding_status"]["first_found_date"])
    last_seen_date = pd.to_datetime(finding["finding"]["finding_status"]["last_seen_date"])
    #Set source
    source = "Veracode"
    if type(tags) is list:
        tags = "; ".join(tags)

    bug_description = finding["finding"]["description"]
    bug_resolution = finding["finding"]["finding_status"]["resolution"]
    resolution_status = finding["finding"]["finding_status"]["resolution_status"]

    if "annotations" in finding["finding"].keys():
        bug_comments = finding["finding"]["annotations"]
    else:
        bug_comments = "None"
    if finding["finding"]["scan_type"] == "STATIC":
        flaw_url = "<a href=" + flaw_url + str(finding["finding"]["issue_id"]) + "> Flaw Link</a>"
        scan_type = "STATIC"
        bug_title = ("[Veracode Flaw]" + " [" + finding["finding"]["scan_type"] + "] [" + finding["finding"]["finding_details"]["finding_category"]["name"] + "] [" + finding["app_name"] + "] [" + 'IssueID_' + str(finding["finding"]["issue_id"]) + "]")
        bug_cve = "n/a"
        component_filename = "n/a"
        bug_cwe = finding["finding"]["finding_details"]["cwe"]["id"]
        bug_cwe_data = finding["finding"]["finding_details"]["cwe"]
        attack_vector = finding["finding"]["finding_details"]["attack_vector"]
        file_line_number = finding["finding"]["finding_details"]["file_line_number"]
        bug_category = finding["finding"]["finding_details"]["finding_category"]["name"]
        bug_module = finding["finding"]["finding_details"]["module"]
        bug_cwe = str(finding["finding"]["finding_details"]["cwe"]["id"])
        if "file_name" in finding["finding"]["finding_details"].keys():
            bug_file_name = finding["finding"]["finding_details"]["file_name"]
            bug_details = {
                "bug_file_name": finding["finding"]["finding_details"]["file_name"],
            }
            
        else:
            bug_file_name = "n/a"
            bug_details = {
                "bug_file_name": "n/a",
            }
    elif finding["finding"]["scan_type"] == "SCA":
        scan_type = "SCA"
        bug_cve = finding["finding"]["finding_details"]["cve"]["name"]
        component_filename = finding["finding"]["finding_details"]["component_filename"]
        bug_category = "3rd Party Code"
        bug_module = finding["finding"]["finding_details"]["component_filename"]
        bug_file_name = finding["finding"]["finding_details"]["component_filename"]
        bug_title = ("[Veracode Flaw]" + " [" + scan_type + "] [" + "Component: " + component_filename + "] [" + bug_cve + "] [" + finding["app_name"] + "]")

        bug_details = {
            "bug_cwe": "n/a"
        }
        attack_vector = "n/a"
        bug_cwe = "n/a"
        bug_cwe_data = "n/a"
        file_line_number = "n/a"
        bug_file_name = "n/a"
        bug_details = "n/a"
        file_line_number = "n/a"
    if "procedure" in finding["finding"]["finding_details"].keys():
        bug_procedure = finding["finding"]["finding_details"]["procedure"]
    else:
        bug_procedure = "n/a"
    
    # Set first found data
    first_found_date = pd.to_datetime(finding["finding"]["finding_status"]["first_found_date"])

    if finding["finding"]["finding_details"]["severity"] == 3:
        bug_severity = '3 - Medium'
        #due_date = datetime.datetime.now() + datetime.timedelta(90)
        due_date = first_found_date.date() + datetime.timedelta(90)
    elif finding["finding"]["finding_details"]["severity"] == 2:
        bug_severity = '4 - Low'
        #due_date = datetime.datetime.now() + datetime.timedelta(180)
        due_date = first_found_date.date() + datetime.timedelta(180)
    elif finding["finding"]["finding_details"]["severity"] == 4:
        bug_severity = '2 - High'
        #due_date = datetime.datetime.now() + datetime.timedelta(30)
        due_date = first_found_date.date() + datetime.timedelta(30)
    elif finding["finding"]["finding_details"]["severity"] == 5:
        bug_severity = '1 - Critical'
        #due_date = datetime.datetime.now() + datetime.timedelta(30)
        due_date = first_found_date.date() + datetime.timedelta(30)

    bug = {
        "Title": bug_title,
        "Application": finding["app_name"],
        "Flaw": flaw_url,
        "Status": bug_status,
        "Scan Type": scan_type,
        "First Found Date": first_found_date,
        "Last Seen Date": last_seen_date,
        "Due Date": due_date,
        "Resolution": bug_resolution,
        "Resolution Status": resolution_status,
        "Severity": bug_severity,
        "File Name": bug_file_name,
        "Bug Source": source,
        "CWE": bug_cwe,
        "CWE Data": bug_cwe_data,
        "CVE": bug_cve,
        "Procedure": bug_procedure,
        "Component Filename": component_filename,
        "Attack Vector": attack_vector,
        "File Line Number": file_line_number,
        "Category": bug_category,    
        "Module": bug_module, 
        "Tags": tags,
        "Description": bug_description,
        "Comments": bug_comments,
        "context_guid": finding["finding"]["context_guid"]
    }
    logger.logger_event("workitem.py", "get_workitem", ("Processed bug", bug_title))
    return bug

# Processing bug data to create workitem 
def create_secbug(bug, destination, static_flow_info, app_metadata):

    if destination:
        ado_org = destination["ado_org"]
        ado_project = destination["ado_project"]
        area_path = destination["area_path"]
        url = "https://dev.azure.com/" + ado_org + "/" + ado_project +"/_apis/wit/workitems/$SECBUG?api-version=6.0"
    else:
        url = "https://dev.azure.com/CompanyCybersecurity/VM2/_apis/wit/workitems/$SECBUG?api-version=6.0"
        area_path = "Experimental\\Veracode"
    title = bug["Title"]
    tags = str(bug["Tags"])
    build_direction = "LEFT_TO_RIGHT"
    table_attributes = {"style" : "width:100%"}
    descrption = convert(bug, build_direction=build_direction, table_attributes=table_attributes)
    if static_flow_info:
        build_direction = "LEFT_TO_RIGHT"
        table_attributes = {"style" : "width:100%"}
        additional_findings_details = convert(static_flow_info, build_direction=build_direction, table_attributes=table_attributes)
    else:
        additional_findings_details = "None"

    if "stakeholders" in app_metadata.keys(): # check for stakeholders 
        security_champion = app_metadata["stakeholders"]["security_champions"]
    else:
        security_champions = None
    logger.logger_event("workitem.py", "create_secbug", ("create_secbug", title))
    
    data = [
    {
    'op': 'add',
    'path': '/fields/System.Title',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': title
    },
    {
    'op': 'add',
    'path': '/fields/System.State',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Status"]
    },
    {
    'op': 'add',
    'path': '/fields/Description',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': "@" + security_champion + descrption
    },
    {
    'op': 'add',
    'path': '/fields/Microsoft.VSTS.Common.Severity',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Severity"]
    },
    {
    'op': 'add',
    'path': '/fields/System.History',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Comments"])
    },
    {
    'op': 'add',
    'path': '/fields/System.AssignedTo',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': 'dmitriy.dunavetsky@Company.com'
    },
    {
    'op': 'add',
    'path': '/fields/System.AreaPath',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': area_path
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Category',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Category"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.ComponentFilename',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Component Filename"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Module',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Module"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.CWE',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["CWE"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.CVE',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["CVE"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Source',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Bug Source"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.ScanType',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Scan Type"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.FindingStatus',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Status"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.FindingResolution',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Resolution"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.ResolutionStatus',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Resolution Status"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.FileName',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["File Name"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Application',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Application"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.FirstDetectionDate', # should be FirstFoundDate, if redoing ADO fields
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["First Found Date"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.LastSeenDate',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Last Seen Date"])
    },
    {
    'op': 'add',
    'path': '/fields/Microsoft.VSTS.Scheduling.DueDate',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Due Date"])
    },
    {
    "op": "add",
    "path": "/fields/Custom.AdditionalFindingsDetails",
    "value": additional_findings_details
    },
    {
    "op": "add",
    "path": "/fields/System.Tags",
    "value": tags
    }
    ] 
    try:
        r = requests.post(url, json=data, 
            headers={'Content-Type': 'application/json-patch+json'},
            auth=('', AZURE_DEVOPS_PAT))
    except requests.RequestException as e:
        logger.logger_error("workitem.py", "create_secbug", ("Whoops, got an error!"))
        logger.logger_error("workitem.py", "create_secbug", (e))
    logger.logger_event("workitem.py", "create_secbug", ("created bug:", title))
    logger.logger_event("workitem.py", "create_secbug", (json.dumps(r.json(), indent=4)))
    workitem = r.json()
    return workitem

# Update workitem,
def update_secbug(id, work_item, bug, destination):
    logger.logger_event("workitem.py", "update_secbug", ("Update Secbug", id))
    workitemid = id["id"]
    if destination:
        ado_org = destination["ado_org"]
        ado_project = destination["ado_project"]
        area_path = destination["area_path"]
        url = "https://dev.azure.com/" + ado_org + "/" + ado_project +"/_apis/wit/workitems/" + str(workitemid) + "?api-version=6.0"
    else:
        url = "https://dev.azure.com/CompanyCybersecurity/VM2/_apis/wit/workitems/" + str(workitemid) + "?api-version=6.0"
        area_path = "Experimental\\Veracode"

    workitemid = str(id["id"])
    title = bug["Title"]
    status = bug["Status"]
    build_direction = "LEFT_TO_RIGHT"
    table_attributes = {"style" : "width:100%"}
    descrption = convert(bug, build_direction=build_direction, table_attributes=table_attributes)
    logger.logger_event("workitem.py", "update_secbug", ("update_secbug", title))
    logger.logger_event("workitem.py", "update_secbug", (bug))
    data = [
    {
    'op': 'replace',
    'path': '/fields/System.Title',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': title
    },
    {
    'op': 'replace',
    'path': '/fields/System.State',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': status
    },
    {
    'op': 'replace',
    'path': '/fields/Microsoft.VSTS.Common.Severity',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Severity"]
    },
    {
    'op': 'replace',
    'path': '/fields/Description',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': descrption
    },
    {
    'op': 'add',
    'path': '/fields/System.History',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': "<h2>updated by automation:</h2>"
    },

    # {
    # 'op': 'add',
    # 'path': '/fields/System.AssignedTo',
    # 'from': 'dmitriy.dunavetsky@Company.com',
    # 'value': 'dmitriy.dunavetsky@Company.com'
    # },
    {
    'op': 'replace',
    'path': '/fields/System.AreaPath',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': area_path
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.Category',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Category"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.ComponentFilename',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Component Filename"]
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.Module',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["Module"]
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.CWE',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["CWE"]
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.CVE',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': bug["CVE"]
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.Source',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Bug Source"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.ScanType',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Scan Type"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.FindingStatus',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': status
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.FindingResolution',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Resolution"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.ResolutionStatus',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Resolution Status"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.FileName',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["File Name"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.Application',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Application"])
    },    
    {
    'op': 'replace',
    'path': '/fields/Custom.FirstDetectionDate',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["First Found Date"])
    },
    {
    'op': 'replace',
    'path': '/fields/Custom.LastSeenDate',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Last Seen Date"])
    },
    {
    'op': 'replace',
    'path': '/fields/Microsoft.VSTS.Scheduling.DueDate',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': str(bug["Due Date"])
    }
    ]
    logger.logger_event("workitem.py", "update_secbug", (json.dumps(data, indent=4)))
    try:
        r = requests.patch(url, json=data, 
            headers={'Content-Type': 'application/json-patch+json'},
            auth=('', AZURE_DEVOPS_PAT))
    except requests.RequestException as e:
        logger.logger_error("workitem.py", "create_secbug", ("Whoops, got an error!"))
        logger.logger_error("workitem.py", "create_secbug", (e))   
    logger.logger_event("workitem.py", "update_secbug", ("updated bug:", title))
    logger.logger_event("workitem.py", "update_secbug", (json.dumps(r.json(), indent=4)))
    workitem = r.json()
    return workitem

# Update workitem,
def add_comment_secbug(id, comment, destination):
    logger.logger_event("workitem.py", "add_comment_secbug", ("Update Secbug", id))
    workitemid = id["id"]
    if destination:
        ado_org = destination["ado_org"]
        ado_project = destination["ado_project"]
        area_path = destination["area_path"]
        url = "https://dev.azure.com/" + ado_org + "/" + ado_project +"/_apis/wit/workitems/" + str(workitemid) + "?api-version=6.0"
    else:
        url = "https://dev.azure.com/CompanyCybersecurity/VM2/_apis/wit/workitems/" + str(workitemid) + "?api-version=6.0"
    data = [
   {
    'op': 'add',
    'path': '/fields/System.History',
    'from': 'dmitriy.dunavetsky@Company.com',
    'value': "<h3>updated by automation:</h3>" + comment
    }
    ]
    try:
        r = requests.patch(url, json=data, 
            headers={'Content-Type': 'application/json-patch+json'},
            auth=('', AZURE_DEVOPS_PAT))
    except requests.RequestException as e:
        logger.logger_error("workitem.py", "create_secbug", ("Whoops, got an error!"))
        logger.logger_error("workitem.py", "create_secbug", (e))   
    logger.logger_event("workitem.py", "add_comment_secbug", ("Added comment to :", ado_org, ado_project, workitemid))
    logger.logger_event("workitem.py", "add_comment_secbug", (json.dumps(r.json(), indent=4)))
    return r