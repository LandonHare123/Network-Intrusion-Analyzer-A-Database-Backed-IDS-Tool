import os
import json
import html
import mariadb
from dotenv import load_dotenv


load_dotenv()


DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
}




def parse_json_column(value):
    """
    Converts a JSON column from MariaDB into a Python dict/list.
    If it is already decoded, return it.
    If it fails, return the original value.
    """
    if value is None:
        return {}


    if isinstance(value, (dict, list)):
        return value


    try:
        return json.loads(value)
    except Exception:
        return value




def format_dict_as_list(value):
    """
    Converts a dictionary like:
        {"192.168.1.1:80": 3, "10.0.0.5:443": 1}


    Into HTML like:
        192.168.1.1:80: 3<br>10.0.0.5:443: 1
    """
    value = parse_json_column(value)


    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            line = f"{html.escape(str(k))}: {html.escape(str(v))}"
            lines.append(line)
        return "<br>".join(lines)


    if isinstance(value, list):
        return "<br>".join(html.escape(str(item)) for item in value)


    return html.escape(str(value))




def main():
    conn = mariadb.connect(**DB_CONFIG)
    cursor = conn.cursor()


    cursor.execute("""
        SELECT
            name,
            ids,
            packets,
            date,
            duration,
            targets,
            participants,
            alerts,
            category
        FROM Incidents
        ORDER BY date DESC
        LIMIT 100
    """)


    rows = cursor.fetchall()


    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>Incident Report</title>
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


        .number {
            text-align: right;
        }
    </style>
</head>
<body>
    <h1>Incident Report</h1>


    <table>
        <tr>
            <th>Name</th>
            <th>Packet IDs</th>
            <th>Packets</th>
            <th>Date / Time</th>
            <th>Duration</th>
            <th>Targets</th>
            <th>Participants</th>
            <th>Alerts</th>
            <th>Categories</th>
        </tr>
"""


    for row in rows:
        name = row[0]
        ids = row[1]
        packets = row[2]
        incident_date = row[3]
        duration = row[4]
        targets = row[5]
        participants = row[6]
        alerts = row[7]
        category = row[8]


        html_content += f"""
        <tr>
            <td>{html.escape(str(name))}</td>
            <td>{html.escape(str(ids))}</td>
            <td class="number">{html.escape(str(packets))}</td>
            <td>{html.escape(str(incident_date))}</td>
            <td>{html.escape(str(duration))}</td>
            <td>{format_dict_as_list(targets)}</td>
            <td>{format_dict_as_list(participants)}</td>
            <td>{format_dict_as_list(alerts)}</td>
            <td>{format_dict_as_list(category)}</td>
        </tr>
"""


    html_content += """
    </table>
</body>
</html>
"""


    with open("incident_report.html", "w", encoding="utf-8") as file:
        file.write(html_content)


    cursor.close()
    conn.close()


    print("Created incident_report.html")




if __name__ == "__main__":
    main()
