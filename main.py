import psutil
import os
import hashlib
import requests

# The below 2 commands are for running chkrootkit from python code
# output = os.system("python2 chkrootkit.py")
# print(output)

# variable defined which are used in below code
counter = -1
prcOpenFileList = []
count =0

# Getting a process with PID : 444 (Google chrome for mac right now)
process = psutil.Process(444) # or PID of process

# list holds the path of all the files plus some other data that are opened by process p aka Google Chrome
list = process.open_files()

# Function created that returns a hashed string value and takes path of file as string 
# that is list items that we retrieved above
# this functn also works with files greater than 1MB
def hash_file(filename):
   h = hashlib.sha1()

   # open file for reading in binary mode
   with open(filename,'rb') as file:
       # loop till the end of the file
       chunk = 0
       while chunk != b'':
           # read only 1024 bytes at a time
           chunk = file.read(1024)
           h.update(chunk)
   # return the hex representation of digest
   return str(h.hexdigest())

# iterating over list to get only the path values from it and
# storing into Open file list of process-444 (prcOpenFileList)
for item in list:
    for data in item:
        counter+=1
        if counter%2==0:
            prcOpenFileList.append(data)

# iterating over process and sending each to VirusTotalAPI
## VT only provides 4 request per minute for public version
for data in prcOpenFileList:
    if count==0:
        print("I m in")
        print(hash_file(data))
        params = {'apikey': 'd21b1c0487ea217eda6e715bd9a6663c05c7a1655a3167767c0d85528a402344', 'resource': hash_file(data)}
        headers = {"Accept-Encoding": "gzip, deflate",
        "User-Agent" : "gzip,  My Python requests library example client or username"}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
        json_response = response.json()
        print(f"The output is : \n\n\n{json_response}")
    else:
        pass
        