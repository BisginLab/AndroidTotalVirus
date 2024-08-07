import vt
import csv
import time
import os
import pandas as pd

API_KEY = 'f8c4555f34f9900ea49bb4648073458467ecce535377870926b38b694f6bc7c6'
INPUT_FILE = '/home/umflint.edu/hrychen/Android-Data/md5_hashes.csv'
OUTPUT_FILE = '/home/umflint.edu/hrychen/Android-Data/virustotal_results.csv'
CHECKPOINT_FILE = '/home/umflint.edu/hrychen/Android-Data/processed_md5s.txt'

def read_csv(input_file):
    processed_md5s = read_checkpoint()

    with open(input_file, 'r') as file:
        reader = csv.DictReader(file)

        index = 2
        for row in reader:
            md5 = row['md5']
            filename = row['filename']
            
            if md5 in processed_md5s:
                print(f"Skipping already processed MD5: {md5}")
                continue
            
            print(f'Processing row {index}: {filename} with MD5 {md5}')
            index += 1
            
            try:
                get_analysis(md5, filename)
                write_checkpoint(md5)
            except Exception as e:
                print(f"Error processing {md5}: {e}")
                break  # Exit the loop on error
            
            time.sleep(4.32)  # Wait for 20 seconds before the next iteration

def get_analysis(md5, filename):
    client = vt.Client(API_KEY)
    try:
        file = client.get_object(f"/files/{md5}")
        stats = file.last_analysis_stats
        print(stats)
        write_to_file(stats, filename, md5)
    except Exception as e:
        print(f"Error fetching report for {md5}: {e}")
    finally:
        client.close()

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

