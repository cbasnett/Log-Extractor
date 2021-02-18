import os, sys, ctypes, gzip, argparse, json
import win32con, win32evtlog, win32evtlogutil, winerror, pywintypes
import xml.etree as etree
import xmltodict

version = '0.2'
apptitle = 'Log Collector'
date = '18/02/2021'
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
            evts.append([event_xml,message])
            
            win32evtlog.EvtUpdateBookmark(bookmark,event)
    return evts

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

def parse(output, gz):
    if not os.path.exists(output):
        os.mkdir(output)
    for c in get_all_channels():
        name = c.replace('/','_')
        try:
            logs = get_logs(c)
        except:
            logs = None
        if logs:
            path = os.path.join(output,name)
            print("Writing {}".format(c))
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
    parser.version = version
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
