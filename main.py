#!/usr/bin/env python3

import json, mariadb,os,time,subprocess
from dotenv import load_dotenv
from datetime import datetime
load_dotenv()

#relevant info stored in .env file imported for use
dbinfo = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME")
}
EVE_FILE=os.getenv("EVE_FILE")

##test file
eventfile = "/home/peyton/eve.json"


##parses time into DATETIME(6) format
def parsetime(ts):
    if not ts:
        return None
    newts = ts[:10] +" " + ts[11:26]
    return newts

def notify(title, message):
    try:
        subprocess.run(["notify-send", title, message],
        check=False)
    except Exception as e:
        print("Notification has failed")
    return

##
def insert(cursor, event):
    notify("New Suricata Alert!!", "Please run AlertViewer")
    sql="""
    INSERT INTO alertevents (
        event_time,
        flowid,
        pcap_cnt,
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        protocol,
        alert_action,
        alert_gid,
        alert_signature_id,
        alert_rev,
        alert_signature,
        alert_category,
        alert_severity,
        raw_json
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""
    alert = event.get("alert", {})
    values= (
        parsetime(event.get("timestamp")),
        event.get("flowid"),
        event.get("pcap_cnt"),
        event.get("src_ip"),
        event.get("src_port"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("proto"),
        alert.get("action"),
        alert.get("gid"),
        alert.get("signature_id"),
        alert.get("rev"),
        alert.get("signature"),
        alert.get("category"),
        alert.get("severity"),
        json.dumps(event),
    )
    cursor.execute(sql, values)

## reads entirety of a .json file and inputs data
def readfile(filename):
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    inserted = 0
    skipped = 0
    failed2load = 0
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                failed2load += 1
                continue
            if event.get('event_type') != "alert":
                skipped+=1
                continue
            insert(cursor, event)
            inserted +=1
        connection.commit()

def monitor_file():
    conn = mariadb.connect(**dbinfo)
    cursor = conn.cursor()


    print(f"Monitoring {EVE_FILE} for Suricata alerts...")
    notify("Activation Successful", "Monitoring Logs")

    with open(EVE_FILE, "r", encoding="utf-8") as file:
    # Start at the end of the file.
    # This means it only imports NEW alerts from this point forward.
        file.seek(0, os.SEEK_END)


        while True:
            line = file.readline()


            if not line:
                time.sleep(0.5)
                continue


            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue


            if event.get("event_type") != "alert":
                continue


            insert(cursor, event)
            conn.commit()


            print(
            f"[ALERT] {event.get('src_ip')}:{event.get('src_port')} "
            f"-> {event.get('dest_ip')}:{event.get('dest_port')} "
            f"{event.get('proto')} | "
            f"{event.get('alert', {}).get('signature')}"
            )

if __name__ == '__main__':
    monitor_file()
    #readfile(eventfile)
   
   
   



