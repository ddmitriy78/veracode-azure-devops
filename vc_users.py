from operator import eq
import sys
import requests
from datetime import date
import datetime
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import pandas as pd
import json
import csv
from json import JSONDecodeError

def write_csv_file(input, filename):
    output = "Writing file", filename
    print("Writing file", "output/" + filename + ".csv")
    file1 = open("output/" + filename + ".csv", 'w')
    file1.write(str(input)) # write to file
    file1.close() 

def users(team):     # api should be a list
    teamid = team["team_id"]
    try: 
        response = requests.get("https://api.veracode.com/api/authn/v2/teams/" + str(teamid) + "?size=5000&page=0", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)
    if response.ok:
        data = response.json()
        for user in data["users"]:
            #print(json.dumps(data, indent=4))
            print(team["team_name"] + ", " + user["user_name"])
    else:
        print(response.status_code)  


if __name__ == "__main__":

    try:
        response = requests.get("https://api.veracode.com/api/authn/v2/teams?size=500&page=0", auth=RequestsAuthPluginVeracodeHMAC(), headers={"User-Agent": "Python HMAC Example"}, verify = True)
    except requests.RequestException as e:
        print("Whoops!")
        print(e)
        sys.exit(1)   

    if response.ok:
        print(response.ok)

    teams = response.json()["_embedded"]
    for team in teams["teams"]:
        users(team)