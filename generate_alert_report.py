import os
import html
import mariadb
from dotenv import load_dotenv


load_dotenv()


DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USERWRITE"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
}




def main():
    conn = mariadb.connect(**DB_CONFIG)
    cursor = conn.cursor()


    cursor.execute("""
        SELECT
            id,
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
            alert_severity
        FROM alertevents
        ORDER BY id DESC
        LIMIT 100
    """)


    rows = cursor.fetchall()


    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Suricata Alert Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f5f5f5;
        }
        h1 {
            color: #333;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            background: white;
            font-size: 14px;
        }
        th, td {
            border: 1px solid #ccc;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }
        th {
            background: #222;
            color: white;
        }
        tr:nth-child(even) {
            background: #eee;
        }
    </style>
</head>
<body>
    <h1>Suricata Alert Report</h1>
    <table>
        <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Flow ID</th>
            <th>PCAP Count</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Action</th>
            <th>GID</th>
            <th>Signature ID</th>
            <th>Rev</th>
            <th>Signature</th>
            <th>Category</th>
            <th>Severity</th>
        </tr>
"""


    for row in rows:
        alert_id = row[0]
        event_time = row[1]
        flowid = row[2]
        pcap_cnt = row[3]
        src = f"{row[4]}:{row[5]}"
        dest = f"{row[6]}:{row[7]}"
        protocol = row[8]
        alert_action = row[9]
        alert_gid = row[10]
        alert_signature_id = row[11]
        alert_rev = row[12]
        signature = row[13]
        category = row[14]
        severity = row[15]


        html_content += f"""
        <tr>
            <td>{html.escape(str(alert_id))}</td>
            <td>{html.escape(str(event_time))}</td>
            <td>{html.escape(str(flowid))}</td>
            <td>{html.escape(str(pcap_cnt))}</td>
            <td>{html.escape(str(src))}</td>
            <td>{html.escape(str(dest))}</td>
            <td>{html.escape(str(protocol))}</td>
            <td>{html.escape(str(alert_action))}</td>
            <td>{html.escape(str(alert_gid))}</td>
            <td>{html.escape(str(alert_signature_id))}</td>
            <td>{html.escape(str(alert_rev))}</td>
            <td>{html.escape(str(signature))}</td>
            <td>{html.escape(str(category))}</td>
            <td>{html.escape(str(severity))}</td>
        </tr>
"""


    html_content += """
    </table>
</body>
</html>
"""


    with open("alert_report.html", "w", encoding="utf-8") as file:
        file.write(html_content)


    cursor.close()
    conn.close()


    print("Created alert_report.html")




if __name__ == "__main__":
    main()

