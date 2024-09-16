import os
import hashlib
import csv

# Base directory containing the APK files
base_dir = '/mnt/data/Android-Data/APKs'
# Output CSV file
output_csv = '/home/umflint.edu/hrychen/Android-Data/md5_hashes.csv'

# Function to calculate the MD5 hash of a file
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to load already processed files
def load_processed_files(csv_file):
    processed_files = set()
    if os.path.exists(csv_file) and os.path.getsize(csv_file) > 0:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                processed_files.add((row['folder'], row['filename']))
    return processed_files

# Main function to process APK files and save MD5 hashes to CSV
def process_apks(base_dir, output_csv):
    processed_files = load_processed_files(output_csv)
    with open(output_csv, 'a', newline='') as csvfile:
        fieldnames = ['folder', 'filename', 'md5']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        if os.stat(output_csv).st_size == 0:
            writer.writeheader()  # Write header only if the file is empty
        
        for i in range(1, 23):  # Loop through eapks1 to eapks22
            apks_dir = os.path.join(base_dir, f'eapks{i}')
            folder_name = f'eapks{i}'
            print(f"Processing folder: {folder_name}")
            for root, _, files in os.walk(apks_dir):
                for file in files:
                    if file.endswith('.apk'):
                        file_path = os.path.join(root, file)
                        if (folder_name, file) not in processed_files:
                            try:
                                md5_hash = calculate_md5(file_path)
                                writer.writerow({'folder': folder_name, 'filename': file, 'md5': md5_hash})
                                processed_files.add((folder_name, file))
                                print(f'Processed {file} from {folder_name}')
                            except Exception as e:
                                print(f"Error processing {file}: {e}")

if __name__ == '__main__':
    process_apks(base_dir, output_csv)



