import hashlib
import requests
import time
import sys
import json

file_name = sys.argv[1] #file argument
api_key = sys.argv[2] 

with open(file_name, "rb") as file: #reading file
    file_hash = hashlib.sha1()
    while chunk := file.read(8192): #calculating hash
        file_hash.update(chunk)

value = file_hash.hexdigest() #hex digested value
print(value) #hash value

#hash lookup
#ed03d990f5b35b60b11de907a1d8433f
url = "https://api.metadefender.com/v4/hash/{0}".format(value)
headers = {
 "apikey": "{0}".format(api_key) #ur own api key
}
response = requests.request("GET", url, headers=headers) #getting the request

def analyze_file(hash_value):
    url = "https://api.metadefender.com/v4/file"
    headers = {
 "apikey": "{0}".format(api_key),
 "Content-Type": "application/octet-stream",
}
    payload = "{\"hash\":[\"" + hash_value + "\"]}" #what you want to upload
    response = requests.request("POST", url, headers=headers, data=payload)
    #print(response.text)
    data2 = response.text
    data3 = json.loads(data2)
    analyze_file.data_id = data3['data_id']
    #print(data3['data_id'])

def data_id_scan(data_id): #scanning the uploaded/new file
    url = "https://api.metadefender.com/v4/file/{0}".format(data_id)
    headers = {
 "apikey": "{0}".format(api_key),
 "x-file-metadata": "{x-file-metadata}"
}
    response3 = requests.request("GET", url, headers=headers) #retrieve data
    #print(response3.text)
    data2 = response3.json()
    #print(data2)
    while data2['scan_results']['progress_percentage'] != 100: #running the whole progress
        response3 = requests.request("GET", url, headers=headers)
        data2 = response3.json()
    #print(data2)
    display_format(data2)

def display_format(data): #show specifics data 
    print("Filename:", file_name)
    print("Overall_status: {status}".format(status=data['scan_results']['scan_all_result_a']))

    for b,d in data['scan_results']['scan_details'].items():
        print("\nEngine: {engine}".format(engine=b))
        print("Thread_found: {thread}".format(thread=d['threat_found'] if d['threat_found'] else 'Clean'))
        print("Scan_result: {result}".format(result=d['scan_result_i']))
        print("Def_time: {time}\n".format(time=d['def_time']))
        
        
if response.status_code == 404: #checking for errors
    #print("Hash not found in the MetaDefender Cloud")
    time.sleep(1)
    analyze_file(value)
    print("File analyzed")
    time.sleep(1)
    print("scanning data ID")
    time.sleep(1)
    print("Completed")
    new_data = data_id_scan(analyze_file.data_id)
    
    
else: #is hash is found run this
    print("Hash was found in the MetaDefender Cloud")
    time.sleep(1)
    #print(value)
    print(response.text)
    data = response.json() #whole dataset 
    display_format(data) #specific display values