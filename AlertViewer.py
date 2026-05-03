#!/usr/bin/env python3

import json, mariadb,os, argparse
from dotenv import load_dotenv
from datetime import date

import ipaddress
load_dotenv()

##relevant info stored in .env file imported for use
dbinfo = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME")
}

##Tree classes, used for storing data for printing, # of children vary therefore an array is used
class Tree:
    def __init__(self, data):
        self.root = TreeNode(data)

class TreeNode:
    def __init__(self, data):
        self.data = data
        self.children = []


##Used to print data to screen after tree is populated, keeps track of depth for padding the string
def preOrderTraversal(depth, root):
    padding = ""
    i = 0
    while i < depth:
        padding += "      "
        i +=1
    try:
        jdata = json.loads(root.data)
        for k,v in jdata.items():
            print(padding+str(k) +": "+str(v))
    except json.JSONDecodeError:
        if isinstance(root.data, list):
            for x in root.data:
                print(padding + x)
        else:
            z = 0
            for y in root.data.split(","):
                print(padding[z:] + y)
                if z == 0:
                    z = 1
    except TypeError:
        print(padding + str(root.data))
    except AttributeError:
        print(padding + str(root.data))
    if root.children:
        for x in root.children:
            preOrderTraversal(depth+1, x)

## incident class, sorts and stores all relevant information per incident
class Incident:
    incidentcount = 0
    ## If a packet is either out of bounds for another incident or the first packet it becomes the Holotype of a new incident object
    ## Its specific metadata (Date Time) become the definition for time inspection on following packets
    def __init__(self, Holotype):
        self.ids = []#
        self.alerts = {}#
        self.packets = 0#
        self.targets = {}#
        self.incidentdate = ""#
        self.incidenttime = None#
        self.incidentdatetime = None
        self.duration = 0.0#
        self.participants = {}#
        self.category = {} #
        self.Holotype = Holotype
        self.Name = None #

        Incident.incidentcount += 1

        self.alerts[Holotype[13]] = 1
        self.packets += 1
        self.targets[str(Holotype[6]) + ":" + str(Holotype[7])] = 1
        self.ids.append(int(Holotype[0]))
        self.ids.append(int(Holotype[0]))
        self.incidentdatetime=Holotype[1]
        self.incidentdate = str(Holotype[1]).split(" ")[0]


        self.participants[str(Holotype[4]) + ":" + str(Holotype[5])] = 1
        self.category[Holotype[14]] = 1


        self.Name = "Incident " + self.incidentdate + " " + str(Incident.incidentcount)

    ## adds a packts data to the Incident incrementing where relevant and appending where relevant
    def insertPacket(self, Member):
        self.packets += 1
        self.ids[1] = int(Member[0])

        self.alerts[Member[13]] = self.alerts.get(Member[13], 0) + 1

        target = str(Member[6]) + ":" + str(Member[7])
        self.targets[target] = self.targets.get(target, 0) + 1

        participant = str(Member[4]) + ":" + str(Member[5])
        self.participants[participant] = self.participants.get(participant, 0) + 1

        self.category[Member[14]] = self.category.get(Member[14], 0) + 1
        self.duration = (Member[1] - self.incidentdatetime).total_seconds()

    ##Once Incidents are defined and stored the program handles IPs using this class, similar to Incidents
class IPs:

    ##A new IP object is created if the IP doesn't already exist in the IPAdresses table or in iparray(stores ip objects)
    ##It is passed the array of Incident Objects to examine and determine if it is a member of them
    def __init__(self, Source, Incidents):


        self.ip = ""
        self.incidents = []
        self.targets = {}
        self.signature = {}
        self.category = {}

        ##Determines incident memberships
        self.ip = str(Source[4])
        for x in Incidents:
            for k,v in x.participants.items():
                if (k.split(":")[0]) == self.ip and not(x.Name in self.incidents):
                    self.incidents.append(x.Name)

        ##Created keys in relevant dicts and increments by 1
        target = str(Source[6]) + ":" + str(Source[7])
        self.targets[target] = self.targets.get(target, 0) + 1
        self.signature[Source[13]] = self.signature.get(Source[13], 0) + 1
        self.category[Source[14]] = self.category.get(Source[14], 0) + 1

    ##adding another packets info to IP object, just incrementing keys by 1
    def insertPacket(self, Source):
        target = str(Source[6]) + ":" + str(Source[7])
        self.targets[target] = self.targets.get(target, 0) + 1
        self.signature[Source[13]] = self.signature.get(Source[13], 0) + 1
        self.category[Source[14]] = self.category.get(Source[14], 0) + 1

##updates env variable for persistent behavior (AI)
def update_env_variable(filename, key, value):
    lines = []
    found = False
    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip().startswith("#") or "=" not in line:
                lines.append(line)
                continue

            current_key = line.split("=", 1)[0].strip()

            if current_key == key:
                lines.append(f"{key}={value}\n")
                found = True
            else:
                lines.append(line)

    if not found:
        lines.append(f"{key}={value}\n")

    with open(filename, "w", encoding="utf-8") as file:
        file.writelines(lines)

##Gets all the data from the raw table used by sortIPs and sortIncident functions returns a tuple all the rows
def getValues():
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    # id eventtime flowid pcapcnt srcip srcport destip destpot protocol action gid
    # 0     1       2        3       4   5          6    7       8       9       10
    # sigid rev signature category severity
    #   11   12     13        14      15
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
        WHERE id > ?
        ORDER BY event_time ASC;
    """, (int(os.getenv("DB_CHECKPOINT")),))
    rows = cursor.fetchall()
    cursor.close()
    connection.close()
    return rows

## binSearch used in sortIPs to determine if the IP already has an entry in the table or if a new one is necessary
def binSearch(target, field, start, end):
    if end < start:
        return -1
    midpoint = (end + start) // 2
    if target == field[midpoint]:
        return midpoint
    elif target > field[midpoint]:
        return binSearch(target, field, midpoint+1, end)
    else:
        return binSearch(target, field, start, midpoint-1)

##Once/If new IP objects have been created they are converted into a json and appended to the old table, it is passed here and using insertion sort the updated table is ordered by IP address
def insertionSort(updatedtable):
    for i in range(1, len(updatedtable)):
        current_item = updatedtable[i]
        current_ip = ipaddress.ip_address(current_item[1])
        j = i - 1
        while j >= 0 and ipaddress.ip_address(updatedtable[j][1]) > current_ip:
            updatedtable[j + 1] = updatedtable[j]
            j -= 1
        updatedtable[j + 1] = current_item

    return updatedtable

##determines if the text is or isn't encoded increments the value and returns new data (AI)
def increment_json_value(json_text, key):
    try:
        data = json.loads(json_text)
        data[key] = data.get(key, 0) + 1

        return json.dumps(data)
    except TypeError:
        data = json_text
        data[key] = data.get(key, 0) + 1
        return  (data)
##Clears the old data and writes in the new sorted array
def writeIPs(array):
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    cursor.execute("""TRUNCATE IPAdresses;""")
    sql="""INSERT INTO IPAdresses(
        Ip,
        Incidents,
        Targets,
        Signature,
        Category
    )
    VALUES (?,?,?,?,?)
    """
    for x in array:
        values = (
            x[1],
            json.dumps(x[2]),
            json.dumps(x[3]),
            json.dumps(x[4]),
            json.dumps(x[5]),
        )
        cursor.execute(sql, values)
    connection.commit()

##takes raw data and incident array and determines what to do with the data
## (new object, increment table, increment object data)
def sortIPs(rows, incidentarray):
    iparray = []
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    sql = """SELECT * FROM IPAdresses;"""
    cursor.execute(sql)

    ##returns a tuple not editable
    currenttable = cursor.fetchall()
    currentiptable =  []
    ##turns tuple into list (editable)
    updatedtable = [list(row) for row in currenttable]

    ##turns json into workable datatypes
    for row in updatedtable:
        row[2] = json.loads(row[2])
        row[3] = json.loads(row[3])
        row[4] = json.loads(row[4])
        row[5] = json.loads(row[5])

    ##makes a list of ips currently in the database
    for x in currenttable:
        currentiptable.append(ipaddress.ip_address(x[1]))

    ##iterates through each packet
    for row in rows:
        ##finds index of ip in the table (-1 if not present)
        index = binSearch(ipaddress.ip_address(row[4]), currentiptable ,0,len(currentiptable)-1)
        dupe= False

        #if there are already ip objects check if the packet's ip already has an object
        counter = 0
        if iparray:
            for x in iparray:
                if ipaddress.ip_address(x.ip) == ipaddress.ip_address(row[4]):
                    dupe= True
                    break
                counter += 1
        ##if the packet is not in the database yet
        if index == -1:
            ## and the packet doesn't have an Object
            if not dupe:
                ##create an object for it
                iparray.append(IPs(row,incidentarray))
            else:
                ##otherwise insert it into the object at counter-1

                iparray[counter].insertPacket(row)

        #if the packet is in the database
        else:
            ##prepare values to increment
            target= str(row[6])+":"+str(row[7])
            signature= str(row[13])
            category=str(row[14])
            ##and increment those values
            updatedtable[index][3] = increment_json_value(updatedtable[index][3], target)
            updatedtable[index][4] = increment_json_value(updatedtable[index][4], signature)
            updatedtable[index][5] = increment_json_value(updatedtable[index][5], category)

            ##iterate through incidents from this session and append new incident to the list
            for x in incidentarray:
                for k, v in x.participants.items():
                    if (k.split(":")[0]) == row[4] and not (x.Name in updatedtable[index][2]):
                        updatedtable[index][2].append(x.Name)
                        break

    ## combines the iparray with the updatedtable if new objects were made
    if iparray:
        ##converts object to json and appends to updated table returns sorted table
        for x in iparray:
            newjson = [0,0,0,0,0,0]
            newjson[1] = x.ip
            newjson[2] = x.incidents
            newjson[3] = x.targets
            newjson[4] = x.signature
            newjson[5] = x.category
            updatedtable.append(newjson)
        return insertionSort(updatedtable)
    else:
        ##table remains sorted from previous execution of this script
        return updatedtable

##sort packets by time grouping into individual incidents
def sortIncident(rows):
    incidentarray = []
    newcheckpoint = None

    ##loop through packets
    for row in rows:
        ##newcheckpoint tracks which row the program has most recently processed, used to change .env file so it doesn't need to calculate where to begin
        newcheckpoint = row[0]
        ##if this packet is the first packet (therefore incidentarray is empty) create a new incident
        if not incidentarray:
            incidentarray.append(Incident(row))

        ## the last object in incidentarray in the incident currently being processed
        current_incident = incidentarray[-1]

        ## difference is the time elpased from the start of the incident to this packet
        difference = (row[1] - current_incident.incidentdatetime).total_seconds()

        ## if the difference is less than 5 seconds or less the 1.5x the current duration
        if difference < 5 or difference < (1.5 * current_incident.duration):
            ##add the packet to the incident
            current_incident.insertPacket(row)
        else:
            ##otherwise check to see if the packet is on a new day (reset incident count for the new day)
            if (str(row[1])).split(" ")[0] != incidentarray[-1].incidentdate:
                Incident.incidentcount = 0
            ##and add a new incident
            incidentarray.append(Incident(row))
    ##if there was no new incidents that means no packets were flagged since the last time running therefore the checkpoint remains the same
    if not newcheckpoint:
        newcheckpoint = os.getenv("DB_CHECKPOINT")
    return incidentarray, newcheckpoint

##writes the incident to the database
def writeIncident(incidentarray):
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    sql = """
        INSERT INTO Incidents (
            name,
            ids,
            packets,
            date,
            duration,
            targets,
            participants,
            alerts,
            category
        )
        VALUES(?,?,?,?,?,?,?,?,?)"""
    for x in incidentarray:
        values = (
            x.Name,
            (str(x.ids[0])+"-"+str(x.ids[1])),
            x.packets,
            x.incidentdatetime,
            x.duration,
            json.dumps(x.targets),
            json.dumps(x.participants),
            json.dumps(x.alerts),
            json.dumps(x.category)
            )
        cursor.execute(sql, values)
    connection.commit()


##prints the IPs from table to the terminal
def printIPs():
    #gather data from the table
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    sql= """SELECT * FROM IPAdresses;"""
    cursor.execute(sql)
    ips = cursor.fetchall()
    columns = [column[0] for column in cursor.description]

    #create new tree for IPs
    IPTree = Tree("IP Addresses")
    datacategory = ("Incidents","Targets","Alerts")

    ##the ips array is an array that contains jsons where each element is a IP address and its data
    ## this algorithm add nodes to the tree containing cleaned data from the ips array or data from the datacategory tuple in the correct order
    for x in ips:
        IPnode = TreeNode(x[1])
        IPTree.root.children.append(IPnode)
        i=2
        for y in datacategory:

            catNode = TreeNode(y)
            IPnode.children.append(catNode)
            if i == 2:
                if isinstance(x[i],str):
                    cleanstr = ""
                    for z in x[i][2:-2]:
                        if not z == "\"":
                            cleanstr += z
                    colNode = TreeNode(cleanstr)
                else:
                    colNode = TreeNode(x[i])
            else:
                colNode= TreeNode(x[i])
            catNode.children.append(colNode)

            if i == 4:
                colNode = TreeNode(x[i+1])
                catNode.children.append(colNode)
            i += 1

    ##then it preorder traverses the tree printing to terminal
    preOrderTraversal(0,IPTree.root)
    cursor.close()
    connection.close()

##functions the exact same as printIPS gather data from table iterates through incidents arranges tree appropriately and sends to preorder for traversal/printing
def printIncidents():
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    sql = sql = """
        SELECT * FROM Incidents"""
    cursor.execute(sql)
    incidents = cursor.fetchall()
    columns = [column[0] for column in cursor.description]
    IncidentTree = Tree("Incidents")
    datacategory = ("Packets:","Time:","Belligerents:","Alerts:")

    for x in incidents:
        count = 1
        IncidentNode = TreeNode(x[0])
        IncidentTree.root.children.append(IncidentNode)
        for y in datacategory:
            catNode = TreeNode(y)
            IncidentNode.children.append(catNode)
            colNode = TreeNode(columns[count])
            catNode.children.append(colNode)
            colNode.children.append(TreeNode(x[count]))
            count += 1
            colNode2 = TreeNode(columns[count])
            catNode.children.append(colNode2)
            colNode2.children.append(TreeNode(x[count]))
            count += 1
    preOrderTraversal(0, IncidentTree.root)
    cursor.close()
    connection.close()

## determines if the date is the same (thus we need the previous increment) or new day and therefore reset the .env DAYIN
def findTime():
    lastrun= os.getenv("DAYRUN")
    increment = os.getenv("DAYIN")
    if lastrun == (date.today()).strftime("%Y-%m-%d"):

        Incident.incidentcount= int(increment)
    else:

        update_env_variable(".env","DAYIN",0)

## Clears the Ip and Incident table from command line
def clearDatabase(table):
    connection = mariadb.connect(**dbinfo)
    cursor = connection.cursor()
    sql= """TRUNCATE """+table+""";"""
    cursor.execute(sql)
    connection.commit()
    cursor.close()
    connection.close()
    return
if __name__ == '__main__':
    ## setups up command line arguements
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--print",
        help = "Prints selected database to screen(In or Ip)",
        choices=["In","Ip"]
    )
    parser.add_argument(
        "-c",
        "--clear",
        help="Clears specified table(In, Ip or Both)",
        choices=["In","Ip","Both"]
    )
    args = parser.parse_args()

    ##determine what arguements where passed and acts accordingly
    if args.print is None and args.clear ==None:
        print("Fetching raw data")
        rows = getValues()
        findTime()
        print("Preparing Incidents")
        incidents, newcheckpoint = sortIncident(rows)
        writeIncident(incidents)
        print("Preparing IPs")
        ips = sortIPs(rows, incidents)
        writeIPs(ips)
        print("Updating database")
        update_env_variable(".env","DB_CHECKPOINT",newcheckpoint)
        update_env_variable(".env","DAYRUN",date.today())
        update_env_variable(".env","DAYIN",Incident.incidentcount)
        print("Done")
    elif args.print == "In":
        printIncidents()
    elif args.print == "Ip":
        printIPs()
    elif args.clear == "Both":
        clearDatabase("Incidents")
        clearDatabase("IPAdresses")
    elif args.clear == "In":
        clearDatabase("Incidents")
    elif args.clear == "Ip":
        clearDatabase("IPAdresses")
    else:
        print("Please enter a valid argument")

