import os
import sys
import time
import hashlib
import requests

API_Key="15eddf7eefd98207f0e794f6497f8bb12022bd45462a586fa5c187ff6b2b0b47"

def scan_directory(path):
    file_lists=[]
    for subdir,root,files in os.walk(path):
        for file in files:
            file_path = os.path.join(subdir, file)
            if file_path.endswith(('.exe', '.bat', '.vbs', '.js', '.scr', '.dll', '.py', '.c++', ".deb")):
                file_lists.append(file_path)
    print("We found some files that could be viruses.")
    print("Start scanning files....")
    count()
    print(file_lists)
    scan_files(file_lists)


def count():
    for i in range(5):
        time.sleep(1)


def  scan_files(file_lists):
    infected_files=[]
    for file in file_lists:
        print("\nScanning... : {}".format(file))
        file_hash = hash_file(file)
        print("File MD5 Hash: {}".format(file_hash))

        if file_hash:
            if check_with_virustotal(file_hash):
                print("Malware Detected --> File name: {}".format(f))
                infected_files.append(f)
    print("Infected files found : {}".format(infected_files))



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


def  check_with_virustotal(file_hash):
    url = "https://www.virustotal.com/api/v3/files/{}".format(file_hash)
    headers = {"x-apikey" : API_Key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.join()
        if json_response["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
            return True
    return False


if __name__ == "__main__":
    path = input("Enter the file path : ")
    scan_directory(path)