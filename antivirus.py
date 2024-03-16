import os
import sys
import time
import hashlib
import requests

from colorama import Fore, Back, Style

 # change your own virustotal API key
API_Key="372033812703b4ac73a07c0cd82ae06fd7a0490f0c4d4407b569730112f28b09"

def scan_directory(path):
    file_lists=[]

    if path.endswith('/'):  
        for subdir,root,files in os.walk(path):
            for file in files:
                file_path = os.path.join(subdir, file)
                file_lists.append(file_path)

        print("Start scanning files....")
        count()
        scan_files(file_lists)

    else:
        print("\nScanning... : {}".format(path))
        file_hash = hash_file(path)
        # print("File MD5 Hash: {}".format(file_hash))

        if file_hash:
            if check_with_virustotal(file_hash):
                print("\n")
                print(Fore.RED + "Malware Detected --> File name: {}".format(path))
                print("\n")
                print("Infected file found : {}".format(path))
                print(Style.RESET_ALL)
                delete_file(path)
            else:
                    print("\n")
                    print("No Infected files found")
                    print("\n")
                    print("See You ...")
                    print("\n")
                    input("Press any key to exit...")



def count():
    for i in range(5):
        time.sleep(1)



def  scan_files(file_lists):
    infected_files=[]
    for file in file_lists:
        print("\nScanning... : {}".format(file))
        file_hash = hash_file(file)

        if file_hash:
            if check_with_virustotal(file_hash):
                print("\n")
                print(Fore.RED +"Malware Detected --> File name: {}".format(file))
                print(Style.RESET_ALL)  
                infected_files.append(file)
                print(Style.RESET_ALL)
                
    if len(infected_files)!=0:
        print("\n")
        print("Malware Files : \n")
        for i in infected_files:    
            print(i)
        delete_file(infected_files)
    else:
        print("\n")
        print("See You ...")
        print("\n")
        input("Press any key to exit...")


def hash_file(file_path):
    hasher = hashlib.md5()

    try:
        with open(file_path, "rb") as file:
            buffer = file.read()
            hasher.update(buffer)
            return hasher.hexdigest()

    except Exception as e:
        print("Could not read the file. Error: {}".format(e))
        return None


def check_with_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_Key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        if json_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
            return True
    return False

def delete_file(file):
    if isinstance(file, list): 
        print("\n") 
        delete_or_not = input("Would you like to delete the infected files? (y/n): ")
        print("\n")
        if delete_or_not.lower() == 'y':
            for f in file:  
                if os.path.isfile(f): 
                    os.remove(f) 
                    print("File removed : {}".format(f))
    else:
        print("\n")
        delete_or_not = input("Would you like to delete the infected file? (y/n): ")
        print("\n")
        if delete_or_not.lower() == 'y':
            if os.path.isfile(file):  
                os.remove(file)  
                print("File removed : {}".format(file))






if __name__ == "__main__":
    path =  input("Enter the file path : ")
    scan_directory(path)