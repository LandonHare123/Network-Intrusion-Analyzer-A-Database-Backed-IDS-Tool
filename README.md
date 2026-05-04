incident_report.py ip_report.py and generate_alert.py are all AI generated scripts used to quickly validate AlertViewer.py and main.py write behavior on the database prior to adding read functions

included is a sample json file eve.json to test the program use main.py with the readfile function on it to populate the first table


in order to run AlertViewer.py and main.py you need to set up a database and a .env as follows

.env file

DB_HOST=localhost
DB_PORT=3306
DB_USER=testuser
DB_PASSWORD=testpass
DB_NAME=suricatadb
DB_CHECKPOINT=0
EVE_FILE=(your path to eve file)
DAYRUN=2026-02-01
DAYIN=0

and for the database install mariadb run it and execute these commands in order


CREATE DATABASE suricatadb;

USE suricatadb;

CREATE TABLE alertevents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_time DATETIME(6),
    flowid BIGINT,
    pcap_cnt BIGINT,
    src_ip VARCHAR(45),
    src_port INT,
    dest_ip VARCHAR(45),
    dest_port INT,
    protocol VARCHAR(10),
    alert_action VARCHAR(50),
    alert_gid INT,
    alert_signature_id INT,
    alert_rev INT,
    alert_signature VARCHAR(255),
    alert_category VARCHAR(255),
    alert_severity INT,
    inserted_at
);

CREATE TABLE Incidents (
    name VARCHAR(100) PRIMARY KEY,
    ids VARCHAR(50),
    packets INT,
    date DATETIME(6),
    duration DECIMAL(10,6),
    targets JSON,
    participants JSON,
    alerts JSON,
    category JSON
);

CREATE TABLE IPAdresses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    Ip VARCHAR(45),
    Incidents JSON,
    Targets JSON,
    Signature JSON,
    Category JSON
);

CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'testpass';

GRANT ALL PRIVILEGES ON suricatadb.* TO 'testuser'@'localhost';

FLUSH PRIVILEGES;
