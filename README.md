# Veracode & ADO Integration Security Python Project

## Functionality

### Export findings from Veracode for all applications
The automation program imports Veracode findings (flaws) for application profiles specified in the security_metadata.json 
 - Veracode API settings 
 - It is possible to configure import of findings from Veracode, consult Veracode REST API documentation

        api_static = (static_scan, annotations_api, violates_policy_api)
        api_sca = (sca_scan, cvss_gte5, annotations_api)

 - Findings are processed to created ADO SECBUG Work Items.
 - Metadata for each finding is extracted to be used  in custom fields when creating or editing ADO workitems
 - Once each finding is processed, program checks if corresponding ADO workitem exists. Check is based on a unique name. 

        [Veracode Flaw] [SCA] [Component: bcprov-jdk15on-1.68.jar] [SRCCLR-SID-27749] [Veracode Profile Name]

 - If program does not find corresponding workitem to Veracode finding the program creates a new workitem
 - If finding has corresponding workitem, program checks if the State and the Finding Resolutions Status is in sync, if not it updates the workitem, currently this is the only mismatch of data between finding and workitem that will trigger the update
 - Automatically set Due Date of the workitem based on the policy. Due Date is based on the first seen date of the finding
    - Medium 90 days, High & Very High is 30 Days
 - During the workitem update a new comment with the recent details is add.
 - Cut off date compared to last seen date of the finding. If more then a year old, it will not be imported
 - Create link to the veracode flaw in the description of the work item
 - me

 ### Findings and work items processing logic
  - Veracode findings are imported based on the API configuraton query
  - The logic for processing Veracode findings is based on custom fields. Custom fields should be added to the work item: 
  - Custom.MitigationAction: This fields supports 4 mitigation actions in Veracode. Set 4 actions to:
    - Application Design
    - Network Environment 
    - OS Environment
    - Request Risk Acceptance
  - Custom.MitigationApproved: This fields supports 2 actions:
    - ACCEPTED
    - REJECTED
 - If the imported Work Item is in State: "New" no actions will be done by this automation 
 - Once the Work Item is advanced to another State the automation will evalute the "Custom.MitigationAction" & "Custom.MitigationApproved" fields. 
 - Once "Custom.MitigationAction" is set to one of the 4 options the "Mitigation Action" will be performed in Veracode. This will update Veracode finding to "PROPOSED" Resolution Status. 
 - Then the "Custom.MitigationApproved" should be set to either "APPROVED" or "REJECTED"
    - If APPROVED, this will approve mitigation in Veracode and Close the Work Item. 
    - If REJECTED, this will reject mitigation in Veracode and move work item to New.
 - If automation detects that findings in Veracode is closed but imported work item is open it will close the work item. This is most like because the findings was addressed by code remediation.  
 
 ### Future enhancements
 - [PRIORITY 1] need to find where to host the application
 - [DONE][PRIORITY 1] add a link to the Veracode flaw into the workitem.
 - [DONE]create a configuration file to be able to control execution of the program
    - [DONE]added vc_modules.json, support to import only specified applications in the file
    - [DONE]Support custom ADO projects and AreaPath through configuration file
    - [DONE]Support custome tags
 - [DONE] ability to import specific applications data only
 - ability to assign workitems to specific individual 
 - [DONE] ability to update status and comments in Veracode based on the activity in ADO
 - move workitems Due Date Policy to configuration file

##### Beta1
- added python multi threding to increase speed. currently configured to run 10 threads
- added First Seen Date & Last Seen Date from Veracode to be imported
- added ability to reac from vc_metadata.json file to configure scans. support Applications to Import
- added file export 
- added link to the veracode flaw

 ### Fields 

    data = [
    {
    'op': 'add',
    'path': '/fields/System.Title',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': title
    },
    {
    'op': 'add',
    'path': '/fields/System.State',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': bug["Status"]
    },
    {
    'op': 'add',
    'path': '/fields/Description',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': descrption
    },
    {
    'op': 'add',
    'path': '/fields/Microsoft.VSTS.Common.Severity',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': bug["Severity"]
    },
    {
    'op': 'add',
    'path': '/fields/System.History',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Comments"])
    },
    # {
    # 'op': 'add',
    # 'path': '/fields/System.AssignedTo',
    # 'from': 'dmitriy.dunavetsky@ceridian.com',
    # 'value': 'dmitriy.dunavetsky@ceridian.com'
    # },
    {
    'op': 'add',
    'path': '/fields/System.AreaPath',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': 'Experimental\\Veracode'
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Category',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Bug Category"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.ComponentFilename',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': bug["Component Filename"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Module',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': bug["Bug Module"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.CWE',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': bug["CWE"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.CVE',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': bug["CVE"]
    },
    {
    'op': 'add',
    'path': '/fields/Custom.Source',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Bug Source"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.ScanType',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Scan Type"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.VC_Status',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Status"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.VC_Resolutions_Status',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Resolutions_Status"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.FileName',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["File Name"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.VC_Application',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Application Profile Name"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.FirstDetectionDate',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["First Found Date"])
    },
    {
    'op': 'add',
    'path': '/fields/Custom.LastSeenDate',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Last Seen Date"])
    },
    {
    'op': 'add',
    'path': '/fields/Microsoft.VSTS.Scheduling.DueDate',
    'from': 'dmitriy.dunavetsky@ceridian.com',
    'value': str(bug["Due Date"])
    }

#### Release Notes


## Veracode Python HMAC Example

A simple example of usage of the Veracode Python API signing library provided in the [Veracode Documentation](https://docs.veracode.com/r/c_hmac_signing_example_python).

### Setup

Clone this repository:

    git clone https://github.com/veracode/veracode-python-hmac-example.git

Install dependencies:

    cd veracode-python-hmac-example
    pip install -r requirements.txt

Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

### Intergration with Azure DevOps
Integration with Azure DevOps is using Personal Access Token (PAT).  This is something we need to change to a Managed Identity or Service Principal. 

Program is expecting PAT to be in a system variable MY_PAT. 

    export MY_PAT="your token"

### Run

If you have saved credentials as above you can run:

main.py


### Annotation API
https://docs.veracode.com/r/c_annotations_propose_mitigation_rest 

### Deploy as container in AWS
Retrieve an authentication token and authenticate your Docker client to your registry.
Use the AWS CLI:

    aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 392094015516.dkr.ecr.us-west-2.amazonaws.com

Note: If you receive an error using the AWS CLI, make sure that you have the latest version of the AWS CLI and Docker installed.
Build your Docker image using the following command. For information on building a Docker file from scratch see the instructions here 
. You can skip this step if your image is already built:

    docker build -t veracode-ado-integration .

After the build completes, tag your image so you can push the image to this repository:

    docker tag veracode-ado-integration:latest 392094015516.dkr.ecr.us-west-2.amazonaws.com/veracode-ado-integration:latest

Run the following command to push this image to your newly created AWS repository:

    docker push 392094015516.dkr.ecr.us-west-2.amazonaws.com/veracode-ado-integration:latest


#### Build EC2 (Amazon Linux), deploy and run docker container 

    #!/bin/bash
    sudo yum update -y
    sudo yum install docker -y
    sudo service docker start
    sudo usermod -a -G docker ec2-user
    aws configure set region us-west-2
    aws configure set output json
    aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin 392094015516.dkr.ecr.us-west-2.amazonaws.com
    docker pull 392094015516.dkr.ecr.us-west-2.amazonaws.com/veracode-ado-integration:latest
    docker run 392094015516.dkr.ecr.us-west-2.amazonaws.com/veracode-ado-integration:latest 

