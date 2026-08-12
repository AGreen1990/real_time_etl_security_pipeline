import time
import re
import os
import psycopg2
from dotenv import load_dotenv

#Regex pattern that decodes messt log string
APACHE_LOG_PATTERN = r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ "]+) HTTP/[0-9.]+" ([0-9]{3}) ([0-9]+|-)'

def tail_file(file_path):
    """ Acts like the Linux 'tail -f' command to catch live data"""
    #open file in read mode
    with open(file_path, 'r') as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                #if no new line, wait a millisecond and try again
                time.sleep(0.1)
                continue
            #if a new line appears, hand it over to the main loop
            yield line

def parse_log(log_line):
    """ Chops the raw string into a structured dictionary. """
    match = re.search(APACHE_LOG_PATTERN, log_line)
    if match:
        return {
            "ip_address": match.group(1),
            "timestamp": match.group(2),
            "method": match.group(3),
           "endpoint": match.group(4),
            "status_code": match.group(5),
            "bytes": match.group(6)
           }
    return None #if the regex fails to match
# --- 🛡️ NEW: THE DQA LAYER ---
def validate_data(parsed_data):
    """" Tests the data against our business rules"""

    #Rule 1: No missing IP addresses
    if not parsed_data.get('ip_address'):
        return False, "Missing IP Address"
    
    #Rule 2: Status code must be exactly 3 digits and a known code
    valid_codes = ['200', '301', '401', '403', '404', '500']
    if parsed_data.get('status_code') not in valid_codes:
        return False, f"Invalid Status Code: {parsed_data.get('status_code')}"
    
    #if it passes all tests, it is certified clean
    return True, "Data is clean"

# --- 4. Load (New NEON cloud logic)
def setup_database(conn):
    """ Creates the table in Neon if it doesn't exist yet. """
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS apache_logs (
                   id SERIAL PRIMARY KEY,
                   ip_address VARCHAR(50),
                   log_timestamp VARCHAR(100),
                   method VARCHAR(10),
                   endpoint TEXT,
                   status_code VARCHAR(10),
                   bytes VARCHAR(20),
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()
    cursor.close()

def insert_log(conn, data):
    """ Securely injects a clean log into Neon Database """
    cursor = conn.cursor()
    sql = '''
        INSERT INTO apache_logs (ip_address, log_timestamp, method, endpoint, status_code, bytes)
        VALUES (%s, %s, %s, %s, %s, %s)
    '''

    cursor.execute(sql, (data['ip_address'], data['timestamp'], data['method'], data['endpoint'], data['status_code'], data['bytes']))
    conn.commit()
    cursor.close()

# --- 5. Main Engine ---
if __name__ == '__main__':
    LOG_FILE = 'access_log_20260812-124119.log'

    print("☁️ Connecting to Neon Cloud Database...")
    load_dotenv() #loads the secret .env file

    #Establish connection to the cloud
    neon_conn = psycopg2.connect(os.getenv("NEON_DB_URL"))
    setup_database(neon_conn)
    print("✅ Database connected and table ready!")

    ip_tracker = {}
    ALERT_THRESHOLD = 5 # if an IP hits 5 times, flag it!

    print("🎧 Listening to {LOG_FILE} for live data...")

    # Point the watcher at the live file 
    log_stream = tail_file(LOG_FILE)

    #This loop will run forever, catching new lines as they are created
    for raw_log_line in log_stream:
        #Step 1: Parse the raw string
        parsed_data = parse_log(raw_log_line)

        if parsed_data:
            #pass the parsed dictionary through our quality Gatekeeper
            is_valid, message = validate_data(parsed_data)

            if is_valid:
                ip = parsed_data['ip_address']

                #1 Count the visits (adds 1 to their score)
                ip_tracker[ip] = ip_tracker.get(ip, 0) + 1

                # 2. The Security Gate
                if ip_tracker[ip] == ALERT_THRESHOLD:
                    print(f"\n🚨 [SECURITY ALERT] IP {ip} is scanning our network! 🚨\n")
                elif ip_tracker[ip] > ALERT_THRESHOLD:
                    print(f"🛡️ [BLOCKED] Dropping malicious traffic from {ip}")
                    continue # 🛑 The Magic WOrd: Skips the rest of the loop

                # If they are under the limit, send it to the cloud
                insert_log(neon_conn, parsed_data)
                print(f"☁️ UPLOADED-> IP: {parsed_data['ip_address']} | Page: {parsed_data['endpoint']} ")
            else:
                print(f"🚨 DQA REJECTED: {message}")