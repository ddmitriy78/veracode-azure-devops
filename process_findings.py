import json
import os

if __name__ == "__main__":
    your_path = '/Users/p129181/Code/output/'
    files = os.listdir(your_path)
    keyword = 'vc_output'
    for file in files:
        if os.path.isfile(os.path.join(your_path, file)) and ".json" in file:
            f = open(os.path.join(your_path, file),'r')
            data = json.load(f)
            module = {}
            output = {
                "app_name": "",
                "modules": [{
                "module": "",
                "file_name": "",
                "file_path": "",
                "procedure": ""
                }]
            }
            count = 0
            for finding in data:
                print(json.dumps(finding))
                if finding["app_name"] not in output:
                    output["app_name"] = finding["app_name"]
                output = {
                    "app_name": finding["app_name"],
                    "modules": [{
                    "module": finding["finding"]["finding_details"]["module"],
                    "file_name": finding["finding"]["finding_details"]["file_name"],
                    "file_path": finding["finding"]["finding_details"]["file_path"],
                    "procedure": finding["finding"]["finding_details"]["procedure"]
                    }]
                }
                module = {
                    "module": finding["finding"]["finding_details"]["module"],
                    "file_name": finding["finding"]["finding_details"]["file_name"],
                    "file_path": finding["finding"]["finding_details"]["file_path"],
                    "procedure": finding["finding"]["finding_details"]["procedure"]
                }
                if finding["app_name"] not in output:
                    output["modules"].append(module)
                else:
                    output
            f.close()