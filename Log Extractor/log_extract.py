import os, sys, ctypes, gzip, argparse, json
import win32con, win32evtlog, win32evtlogutil, winerror, pywintypes
import xml.etree as etree
import xmltodict
from elasticsearch import Elasticsearch, AuthenticationException
from elasticsearch.helpers import bulk

version = '0.3'
apptitle = 'Log Collector'
date = '29/03/2022'
author = 'Chris Basnett (chris.basnett@mdsec.co.uk)'

def is_admin():
   '''Check if we're being run as an admin'''
   try:
      return ctypes.windll.shell32.IsUserAnAdmin()
   except:
      return False

def get_all_channels():
    e = win32evtlog.EvtOpenChannelEnum()
    channels = []
    channel = win32evtlog.EvtNextChannelPath(e)
    while channel != None:
        channels.append(channel)
        channel = win32evtlog.EvtNextChannelPath(e)
    return channels

def get_all_publishers():
    e = win32evtlog.EvtOpenPublisherEnum()
    publishers = []
    publisher = win32evtlog.EvtNextPublisherId(e)
    while publisher != None:
        publishers.append(publisher)
        publisher = win32evtlog.EvtNextPublisherId(e)
    return publishers

def log_normalise(line):
    format = {
        "Provider": {
            "Name": "",
            "GUID": ""
        },
        "Event": {
            "ID": 0,
            "Version": 0,
            "Level": 0,
            "Created": "",
            "Channel": "",
            "Message": "",
            "Computer": "",
            "UserID": "" 
        },
        "Meta": {}
    }

    event = line['Event']
    eventkeys = event.keys() # Save us calling this a number of times
    # Basic Sanity Check
    if 'Provider' not in eventkeys:	# if there's no provider
        if 'TimeCreated' not in eventkeys:
            return None
    
    if type(event['Provider']) == type(''):
        format['Provider']['Name'] = event['Provider']
    else:
        format['Provider']['Name'] = event['Provider']['Name']
        format['Provider']['GUID'] = event['Provider'].get('Guid','')

    if 'EventID' in eventkeys:
        if type(event['EventID']) != type(''):
            format['Event']['ID'] = int(event['EventID']['Qualifiers'])
        elif event.get('EventID',None):
            format['Event']['ID'] = int(event['EventID'])

    format['Event']['Version'] = int(event.get('Version',0))
    format['Event']['Level'] = int(event.get('Level',0))

    if 'TimeCreated' in eventkeys:
        format['Event']['Created'] = event['TimeCreated']['SystemTime']	# Probably want to save this as an int tbh
    format['Event']['Channel'] = event['Channel']
    if 'Computer' in eventkeys:
        format['Event']['Computer'] = event['Computer']
    if 'Security' in eventkeys:
        if line['Event']['Security']:
            format['Event']['UserID'] = event['Security'].get('UserID',None)

    format['Event']['Message'] = line['Message']

    if event.get('Execution',None):
        for k in event.get('Execution'):
            if k == "ProcessID":
                format['Meta'][k] = int(event['Execution'][k])  # If it's a processid we want an int
            if k == "ThreadID":
                format['Meta'][k] = int(event['Execution'][k])  # If it's a threadid we want an int

    # Sysmon Specific formatting
    if event['Channel'] == "Microsoft-Windows-Sysmon/Operational":
        message = format['Event']['Message']
        format['Meta']['Sysmon'] = {} 
        for item in message.split('\r\n'):
            try:
                key,value = item.split(': ')
                format['Meta']['Sysmon'][key] = value
            except:
                continue
    # Security Process audit specific formatting
    if event['Channel'] == 'Security':
        message = format['Event']['Message']
        if format['Event']['ID'] == 4688:   # If it's a process creation
            format['Meta']['Audit'] = {}
            split = message.split('\r\n\r\n')
            for s in split:
                if 'Process Information' in s:
                    for field in s.split('Process Information:')[1].split('\r\n\t'):
                        try:
                            key, value = field.split(':\t')
                            value = value.strip('\t')
                            key = key.replace(' ','')
                            format['Meta']['Audit'][key] = value
                        except:
                            pass

    return(format)

def get_logs(channel=None):
    evts = []
    flags = win32evtlog.EvtQueryChannelPath
    if channel != None:
        query = win32evtlog.EvtQuery(channel,flags,'*',None)
    else:
        query = win32evtlog.EvtQuery('Security',flags,'*',None)

    
    bookmark = win32evtlog.EvtCreateBookmark()  # In case we want to actually save off our location to allow us to not grab all logs every time.

    events = True
    while events:
        events = win32evtlog.EvtNext(query,100,-1,0)
        context = win32evtlog.EvtCreateRenderContext(win32evtlog.EvtRenderContextSystem)
        for event in events:
            import sys

            result = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventValues, Context=context)
            provider_name_value, provider_name_variant = result[win32evtlog.EvtSystemProviderName]
            try:
                metadata = win32evtlog.EvtOpenPublisherMetadata(provider_name_value)
            except:
                metadata = None # Lazy exception here to make life simple
            
            try:
                message = win32evtlog.EvtFormatMessage(metadata, event, win32evtlog.EvtFormatMessageEvent)
            except:
                message = "The Description for this event could not be found"

            event_xml = win32evtlog.EvtRender(event,win32evtlog.EvtRenderEventXml)
            #evts.append([event_xml,message])
            
            win32evtlog.EvtUpdateBookmark(bookmark,event)
            parsed_event = parse_event([event_xml,message])
            if args.elastic:
                parsed_event = log_normalise(parsed_event)
            
            yield parsed_event
    #return evts

def parse_event(event):
    event,message = event
    evt = {}
    data = json.loads(json.dumps(xmltodict.parse(event)))
    data = data['Event']
    data.pop('@xmlns')  # Get rid of the xml schema horseshit
    for k in data.keys():
        if k == 'EventData':
            ed = {}
            evt['EventData'] = data.get('EventData')
        elif k == 'UserData' :
            ud = {}

        else:
            evnt = {}
            d = data[k]
            for key in d.keys():
                if key != '':
                    if type(d[key]) == dict:    # If there's a key
                        evnt[key] = {}
                        for k in d[key]:
                            if k != '':
                                if '@' in k:
                                    nk = k.split('@')[1]
                                evnt[key][nk] = d[key][k]
                    else:
                        evnt[key] = d[key]
            evt['Event'] = evnt
            evt['Message'] = message
    
    return evt

def parse(args):
    

    if args.elastic:    # If we're telling it the output should be elastic
        client = Elasticsearch(args.output)
        
    else:
        if not os.path.exists(args.output):
            os.mkdir(args.output)

    for c in get_all_channels():
        name = c.replace('/','_')
        path = os.path.join(args.output,name)
        print("Processing: {}".format(c))
        if args.elastic:
            
            try:
                response = bulk(client, get_logs(c),index='log_extract')
            except AuthenticationException:
                print("Problem with Authentication, are you using the correct credentials?")
                import sys
                sys.exit()
            except Exception as E:
                print(E)
                
        else:
            if args.gzip:
                f = gzip.open('{}.gz'.format(path),'w')
        
            else:
                f = open('{}.log'.format(path),'wb')
        
            
            for l in get_logs(c):
                f.write(str(l).encode('utf-8'))
                f.write(b'\n')
            f.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description=apptitle)
    parser.version = version
    parser.add_argument('-g', '--gzip', action="store_true", help='Compress with GZIP')
    parser.add_argument('-o', '--output', action='store', type=str, help='Output Directory or ES server path (http://username:password@host:port',required=True)
    parser.add_argument('-v','--version',action='version')
    parser.add_argument('-e','--elastic',action='store_true')

    args = parser.parse_args()
    os.system('cls')
    print(apptitle)
    print("Version {}\n".format(version))
    print(author)
    print("\n")

    if not args.output:
        parser.print_help()
    else:
        if is_admin():
            parse(args)
        else:
            ctypes.windll.shell32.ShellExecuteW(None, u"runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
