import json
import os
from datetime import date
from datetime import datetime

def logger_start(command):
    if command == "start":
        logger_logs = []
        logger_count = 0
    else:
        logger_logs = None
        logger_count = None
    return {"logger_logs": logger_logs, "logger_count": logger_count}



def logger_event(file, module, message):
    relative_dir = os.path.dirname(__file__)
    today = date.today()
    curDT = datetime.now()
    file_time_stamp = today.strftime("%y-%m-%d")
    timestamp = curDT.strftime("%m-%d-%Y_%H:%M:%S:%s")
    log = {"t": timestamp, "f": file, "m": module, "m": message}

    file_name = file_time_stamp + "_log.txt"
    try:
        file1 = open("logs/" + file_name, "a")  # append mode
    except:
        print("logger.py", "logger_event", ("Didn't find output folder, checking relative path", relative_dir))
        file1 = open( relative_dir + "/logs/" + file_name, "a")
    print(log)
    file1.write(str(log) + "\n")
    file1.close()
    return log

    try:
        file1 = open("output/" + filename + ".json", 'w')
    except:
        relative_dir = os.path.dirname(__file__)
        logger.logger_event("main.py", "write_json_file", ("Didn't find output folder, checking relative path", relative_dir))
        file1 = open( relative_dir + "/output/" + filename + ".json", 'w')

if __name__ == "__main__":
    for x in range(100):
        print(logger_event("filename", "module", "message"))
