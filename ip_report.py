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




def safe_json_load(value):
    """
    Safely convert a JSON string from MariaDB into a Python object.
    If it fails, return the original value.
    """
    if value is None:
        return {}


    if isinstance(value, (dict, list)):
        return value


    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value




def format_json_for_html(value):
    """
    Formats JSON dictionaries/lists nicely for an HTML table cell.
    """
    data = safe_json_load(value)


    if isinstance(data, dict):
        if not data:
            return ""


        lines = []
        for key, count in data.items():
            lines.append(
                f"{html.escape(str(key))}: {html.escape(str(count))}"
            )


        return "<br>".join(lines)


    if isinstance(data, list):
        if not data:
            return ""


        return "<br>".join(html.escape(str(item)) for item in data)


    return html.escape(str(data))




def main():
    conn = mariadb.connect(**DB_CONFIG)
    cursor = conn.cursor()


    cursor.execute("""
        SELECT
            id,
            Ip,
            Incidents,
            Targets,
            Signature,
            Category
        FROM IPAdresses
        ORDER BY INET_ATON(Ip) ASC
    """)


    rows = cursor.fetchall()


    html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>IP Address Report</title>
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


        .id-cell {
            text-align: right;
            width: 60px;
        }


        .ip-cell {
            font-weight: bold;
            white-space: nowrap;
        }
    </style>
</head>
<body>
    <h1>IP Address Report</h1>


    <table>
        <tr>
            <th>ID</th>
            <th>IP Address</th>
            <th>Incidents</th>
            <th>Targets</th>
            <th>Signatures</th>
            <th>Categories</th>
        </tr>
"""


    for row in rows:
        row_id = row[0]
        ip = row[1]
        incidents = row[2]
        targets = row[3]
        signature = row[4]
        category = row[5]


        html_content += f"""
        <tr>
            <td class="id-cell">{html.escape(str(row_id))}</td>
            <td class="ip-cell">{html.escape(str(ip))}</td>
            <td>{format_json_for_html(incidents)}</td>
            <td>{format_json_for_html(targets)}</td>
            <td>{format_json_for_html(signature)}</td>
            <td>{format_json_for_html(category)}</td>
        </tr>
"""


    html_content += """
    </table>
</body>
</html>
"""


    with open("ip_address_report.html", "w", encoding="utf-8") as file:
        file.write(html_content)


    cursor.close()
    conn.close()


    print("Created ip_address_report.html")




if __name__ == "__main__":
    main()

