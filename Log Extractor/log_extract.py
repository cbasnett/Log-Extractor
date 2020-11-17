import win32con
import win32evtlog
import win32evtlogutil
import winerror
import pywintypes
import xmltodict
import xml.etree as etree
import os, sys, ctypes, gzip, argparse, json

version = '0.1'
apptitle = 'Log Collector'
data = '16/11/2020'
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

def get_logs(channel=None):
    evts = []
    flags = win32evtlog.EvtQueryChannelPath
    if channel != None:
        query = win32evtlog.EvtQuery(channel,flags,'*',None)
    else:
        query = win32evtlog.EvtQuery('Security',flags,'*',None)

    bookmark = win32evtlog.EvtCreateBookmark()
    i = 0
    events = True
    while events:
        events = win32evtlog.EvtNext(query,100,-1,0)
        for event in events:
            event_xml = win32evtlog.EvtRender(event,win32evtlog.EvtRenderEventXml)
            evts.append(event_xml)
            i+=1
            win32evtlog.EvtUpdateBookmark(bookmark,event)
    #print(win32evtlog.EvtRender(bookmark,win32evtlog.EvtRenderBookmark))    # Save me off the bookmark so I can resume from here next time
    return evts

def parse_event(event):
    evt = {}
    data = json.loads(json.dumps(xmltodict.parse(event)))
    data = data['Event']
    data.pop('@xmlns')  # Get rid of the xml schema horseshit
    for k in data.keys():
        if k == 'EventData':
            ed = {}
            if data.get('EventData',None):
                if data['EventData'].get('Data',None):
                    for d in data['EventData']['Data']:
                        if d:
                            if type(d) == dict:
                                ed[d['@Name']] = d.get('#text',None)
                            else:   # If it's not a dict, let's see if it's a list of =
                                if '=' in d:
                                    lines = d.split('\n')
                                    for l in lines:
                                        key = l.split('=')[0].strip()
                                        try:
                                            value = l.split('=')[1].strip()
                                        except:
                                            value = None
                                        ed[key] = value
                    evt['EventData'] = ed
        elif k == 'UserData' :
            ud = {}

        else:
            evnt = {}
            d = data[k]
            for key in d.keys():
                if type(d[key]) == dict:    # If there's a key
                    evnt[key] = {}
                    for k in d[key]:
                        if '@' in k:
                            nk = k.split('@')[1]
                        evnt[key][nk] = d[key][k]
                else:
                    evnt[key] = d[key]
            evt['Event'] = evnt
    
    return evt

def parse(output, gz):
    for c in get_all_channels():
        name = c.replace('/','_')
        try:
            logs = get_logs(c)
        except:
            logs = None
        if logs:
            path = os.path.join(output,name)
            if gz:
                f = gzip.open('{}.gz'.format(path),'w')
            else:
                f = open('{}.log'.format(path),'wb')
            for l in logs:
                f.write((json.dumps(parse_event(l)).encode('utf-8')))
                f.write(b'\n')
            f.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description=apptitle)
    parser.version = '0.1'
    parser.add_argument('-g', '--gzip', action="store_true", help='Compress with GZIP')
    parser.add_argument('-o', '--output', action='store', type=str, help='Output Directory',required=True)
    parser.add_argument('-v','--version',action='version')

    args = parser.parse_args()
    os.system('cls')
    print(apptitle)
    print("Version {}\n".format(version))
    print(author)
    print("\n")

    if not args.output:
        parser.print_help()

    elif args.gzip:
        if is_admin():
            parse(args.output, True)
        else:
            ctypes.windll.shell32.ShellExecuteW(None, u"runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
    else:
        if is_admin():
            parse(args.output, False)
        else:
            ctypes.windll.shell32.ShellExecuteW(None, u"runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
        

    
    

    
