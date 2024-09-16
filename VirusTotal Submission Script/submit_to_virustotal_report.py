import requests
import csv
import time
import os
import json

API_KEY = 'f8c4555f34f9900ea49bb4648073458467ecce535377870926b38b694f6bc7c6'
BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
INPUT_FILE = '/home/umflint.edu/hrychen/Android-Data/md5_hashes.csv'
OUTPUT_FILE = '/home/umflint.edu/hrychen/Android-Data/virustotal_results.csv'
CHECKPOINT_FILE = '/home/umflint.edu/hrychen/Android-Data/processed_md5s.txt'
JSON_OUTPUT_DIR = '/home/umflint.edu/hrychen/Android-Data/json_reports/'  # Base directory to save JSON reports

def read_csv(input_file):
    processed_md5s = read_checkpoint()

    with open(input_file, 'r') as file:
        reader = csv.DictReader(file)

        index = 2
        for row in reader:
            folder = row['folder']  # Read the folder name from the CSV
            md5 = row['md5']
            filename = row['filename']
            
            if md5 in processed_md5s:
                print(f"Skipping already processed MD5: {md5}")
                continue
            
            print(f'Processing row {index}: {filename} with MD5 {md5}')
            index += 1
            
            try:
                get_analysis(md5, folder, filename)
                write_checkpoint(md5)
            except Exception as e:
                print(f"Error processing {md5}: {e}")
                continue  # Continue to the next row on error
            
            time.sleep(4.32)  # Adjusting for the API rate limit

def get_analysis(md5, folder, filename):
    params = {'apikey': API_KEY, 'resource': md5}
    try:
        response = requests.get(BASE_URL, params=params)
        if response.status_code == 200:
            report = response.json()

            # Check if the response has a valid scan report
            if report['response_code'] == 1:
                # Save the full JSON report
                save_json_report(report, folder, md5)

                # Extract the last analysis statistics
                stats = extract_stats_from_report(report)
                print(stats)
                write_to_file(stats, filename, md5)
            else:
                print(f"File {md5} not found on VirusTotal.")
        else:
            print(f"Error fetching report for {md5}: HTTP {response.status_code}")
    except Exception as e:
        print(f"Error fetching report for {md5}: {e}")

def extract_stats_from_report(report):
    """Extracts relevant statistics from the VirusTotal report."""
    stats = {
        'harmless': 0,
        'type-unsupported': 0,
        'suspicious': 0,
        'confirmed-timeout': 0,
        'timeout': 0,
        'failure': 0,
        'malicious': 0,
        'undetected': 0
    }
    scans = report.get('scans', {})
    for engine, result in scans.items():
        if result['detected']:
            if result['result'] in stats:
                stats[result['result']] += 1
            else:
                stats['malicious'] += 1
        else:
            stats['undetected'] += 1
    return stats

def write_to_file(stats, filename, md5):
    with open(OUTPUT_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            filename, md5, 
            stats.get('harmless', 0),
            stats.get('type-unsupported', 0),
            stats.get('suspicious', 0),
            stats.get('confirmed-timeout', 0),
            stats.get('timeout', 0),
            stats.get('failure', 0),
            stats.get('malicious', 0),
            stats.get('undetected', 0)
        ])

def save_json_report(report, folder, md5):
    """Save the VirusTotal JSON report to a file, organized by folder."""
    folder_path = os.path.join(JSON_OUTPUT_DIR, folder)  # Use folder from CSV

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)  # Create subdirectory if it does not exist

    json_file_path = os.path.join(folder_path, f"{md5}.json")
    with open(json_file_path, 'w') as json_file:
        json.dump(report, json_file)

def read_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as file:
            processed_md5s = set(line.strip() for line in file)
    else:
        processed_md5s = set()
    return processed_md5s

def write_checkpoint(md5):
    with open(CHECKPOINT_FILE, 'a') as file:
        file.write(f"{md5}\n")

def initialize_output_csv():
    if not os.path.exists(OUTPUT_FILE) or os.stat(OUTPUT_FILE).st_size == 0:
        with open(OUTPUT_FILE, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                'Filename', 'MD5', 'Harmless', 'Type Unsupported', 
                'Suspicious', 'Confirmed Timeout', 'Timeout', 
                'Failure', 'Malicious', 'Undetected'
            ])

def __main__():
    initialize_output_csv()
    read_csv(INPUT_FILE)

__main__()
