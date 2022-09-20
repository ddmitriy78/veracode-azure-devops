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

api_base = "https://api.veracode.com/appsec/"
start_date = datetime.datetime.now() - datetime.timedelta(30)


# Comments Properties
# issue_list
#       Required  String	Comma-separated list of finding IDs. You can use the Findings API to get a list of finding IDs for an application.
# comment
#       Required	String	Enter a brief comment about the findings for issue_list.

# Mitigation Properties
# issue_list:Required	
#       String	Comma-separated list of finding IDs. You can use the Findings API to get a list of finding IDs for an application.
# comment: Required
#       String	Enter a brief comment about the findings for issue_list.
# action: Required	
#       String	Enter one of these mitigation actions:
#     - APPDESIGN states that custom business logic within the body of the application has addressed the finding. An automated process may not be able to fully identify this business logic.
#     - NETENV states that the network in which the application is running has provided an environmental control that has addressed the finding.
#     - OSENV states that the operating system on which the application is running has provided an environmental control that has addressed the finding.
#     - FP, which stands for false positive, states that Veracode has incorrectly identified a finding in your application. If you identify a finding as a potential false positive, Veracode does not exclude the potential false positive from your published report. Your organization can approve a potential false positive to exclude it from the published report. If your organization approves a finding as a false positive, your organization is accepting the risk that the finding might be valid.
#     - LIBRARY states that the current team does not maintain the library containing the finding. You referred the vulnerability to the library maintainer.
#     - ACCEPTRISK states that your business is willing to accept the risk associated with a finding. Your organization evaluated the potential risk and effort required to address the finding.
#     - ACCEPTED Approve the mitigation
example = {
  "issue_list": "319,40, 42",
  "comment": "\rTechnique : M1 : Establish and maintain control over all of your inputs\r\nSpecifics : We are using an encoder for our input.\r\nRemaining Risk : None.\r\nVerification : We must decline, for secret reasons.",
  "action": "NETENV"
}
# https://docs.veracode.com/r/c_rest_annotations_intro 
def vc_annotations(app_name, app_guid, issueid, comment, action):
    
    data = {
        "issue_list": issueid,
        "comment": comment,
        "action": action
    }
    try:

        response = requests.post("https://api.veracode.com/appsec/v2/applications/" + app_guid + "/annotations", json=data, auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example", "Content-Type": "application/json"}, verify = False)
        print("api call to", app_name, "https://api.veracode.com/appsec/v2/applications/" + app_guid + "/annotations")

    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        #sys.exit(1)
    print(response)
    print(response.json())

    try:
        resp_dict = response.json()
        if "findings" in resp_dict.keys():
            print("Successfully update Veracode Issue:", issueid, "in", app_name)
        elif "api_errors" in resp_dict["_embedded"]: # Handle error
            
            print(resp_dict["_embedded"]["api_errors"])
            output = resp_dict["_embedded"]["api_errors"]
    except JSONDecodeError:
        print("Error response could not be searialzed")     
    else:
        print(response.status_code)   
    return response 


