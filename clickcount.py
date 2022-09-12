import argparse
from signal import valid_signals
import time
import os
import re
#from slack_sdk.webhook import WebhookClient
import subprocess
import time
import json
import requests

# create a polling program to monitor for changes to the apache logs
# perhaps can check in at every 5 minutes to give reports
# basically could run the existing script and pipe the results to a slack hook
# clear out any MS or suspected sandbox IPs

# polling global
LAST_EDIT = 1234.5

# slack hook URL
URL = ''

LOGS_DIR = '/var/log/apache2'


# open all log files and find page results
def open_logs(ip_dict, redirect_ips, url='*', report=False):
    regex = re.compile('(.*log$)')
    regex2 = re.compile(r'(.*log.\d$)')
    with os.scandir(LOGS_DIR) as entries:
         for entry in entries:
            if regex.match(entry.name) or regex2.match(entry.name):
#                print(entry)
                ip_dict, redirect_ips = search_log(entry.name, url, ip_dict, redirect_ips, report=report)
    return ip_dict, redirect_ips

def get_useragent(useragents, entry):
    # parse entry to get user agent info
    entry = entry.split('"')
    try:
        e = entry[-2]
        if len(e) > 25:
            if e not in useragents:
                useragents += [e]
    except:
        pass
    # add entry to dict if unique
    
    return useragents

# Helper for searching log files
def search_log(logname, url, ip_dict, redirect_ips, report=False):
    useragents_success = []
    useragents_redirects = []
    regex = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    logfile = os.path.join(LOGS_DIR, logname)
    with open(logfile, 'r') as logs:
#        print(logs)
        for entry in logs:
#            print('line: ' + entry)
            if url in entry and '200' in entry:
                useragents_success = get_useragent(useragents_success, entry)

                ip = regex.search(entry)
                
                # TODO: Record user agent info too.
                ip = str(ip[0])
                ip_dict = unique_ip(ip_dict, ip)
                
#                print(entry)
#                print(ip)
            elif url in entry and '302' in entry:
                useragents_redirects = get_useragent(useragents_redirects, entry)

                ip = regex.search(entry)
                ip = str(ip[0])
                redirect_ips = unique_ip(redirect_ips, ip)
    print("======== 200 User agents ========")
    if report:
        
        for s in useragents_success:
            print(s)
        for r in useragents_redirects:
            print(r)
    return ip_dict, redirect_ips

def unique_ip(ip_dict, ip):
    if ip in ip_dict:
        ip_dict[ip] = ip_dict[ip] + 1
        return ip_dict
    else:
        ip_dict[ip] = 1
        return ip_dict

def whois(ip):
    # Change to whois for linux machine
    who = subprocess.check_output(['whois', ip]).decode('utf-8')
    org = who.find('OrgName:')
    org = who[org:]
    org = org.split('\n')[0]
    # print(org)
    return org

def get_log_times(time_dict):
    regex = re.compile('(.*log$)')
    regex2 = re.compile(r'(.*log.\d$)')
    with os.scandir(LOGS_DIR) as entries:
         for entry in entries:
            if regex.match(entry.name) or regex2.match(entry.name):
                entry_name = os.path.join(LOGS_DIR, entry.name)
                t = os.path.getmtime(entry_name)
                time_dict[entry.name] = t
    return time_dict

def compare_dict_ips(old_dict, new_dict):
    new_clicks = []
    for key in new_dict.keys():
        if key not in old_dict.keys():
            # whois(key)
            new_clicks += [key]
    return new_clicks

# true if a change was made
# false otherwise
def compare_dicts_values(old_dict, new_dict):
    for value in new_dict.values():
        if value not in old_dict.values():
            print('File has been edited')
            return True
    return False

def pollLogs(old_dict_ip, url, time_dict, old_redirect_ips):
    # iterate through log files
    new_dict_ip = dict() # This resets the old dict and doesn't carry over the results unless there is a chnage in the file
    new_time_dict = dict()
    new_redirect_ips = dict()
    regex = re.compile('(.*log$)')
    regex2 = re.compile(r'(.*log.\d$)')
    new_time_dict =  get_log_times(new_time_dict)
    if compare_dicts_values(time_dict, new_time_dict):
        new_dict_ip, new_redirect_ips = open_logs(new_dict_ip, old_redirect_ips, url)
        new_clicks = compare_dict_ips(old_dict_ip, new_dict_ip)
        for click in new_clicks:
            # slack hook send msg
            print(f'New click from: {click}')
            org = whois(click)
            msg = {'text': f'New click from {org} ({click})'}
            msg = {'text': f'New click from ({click})'}
            slack(msg)
            print(msg)
        return new_time_dict, new_dict_ip, new_redirect_ips

    # Could have changes in the mod date, but not valid clicks to report, those would still be covered by the conditional
    # this should be old redirects. Need to fix this to manage / track redirects. 
    # Redirects will really only matter for the final report. 
    return new_time_dict, old_dict_ip, new_redirect_ips


def main(url, sleep=60, report=False):
    allinfo = dict()
    runtime = 0
    
    poll_dict = dict()
    x = 0
    ip_dict = dict()
    redirect_ips=dict()
    while(True):
        if x == 0 or report:
            ip_dict, redirect_ips = open_logs(ip_dict, redirect_ips, url, report=report)
            poll_dict = get_log_times(poll_dict)
            x = 1
            if report:
                # print(ip_dict)
                clicks = clickcount(ip_dict)
                redirects = clickcount(redirect_ips)
                quit()
        # LAST_EDIT, poll_dict = pollLogs(LAST_EDIT, poll_dict, url)

        poll_dict, ip_dict, redirect_ips = pollLogs(ip_dict, url, poll_dict, redirect_ips)
        time.sleep(10)
        runtime += 1
        if runtime == (sleep*6):
            ip_dict = dict()
            ip_dict, redirect_ips = open_logs(ip_dict, redirect_ips, url)
            print(f'redirect ips: {redirect_ips}')
            print(ip_dict)
            allinfo = clickcount(ip_dict)
            print(allinfo)
            # msg = format_info(allinfo)
            # slack(msg)
            runtime = 0
            # send slack message with full update

def getUrlsFromCSV(file):
    with open(file) as f:
        urls = f.read().split(',')
        return urls

def clickcount(ip_dict):
    i = 0
    j = 0
    k = 0
    orgs = []
    for ip in ip_dict:
        print(f'======== {ip} ========')
        org = whois(ip)
        org = org.replace('OrgName:        ','')
        print(org)
        print(f"clickcount: {ip_dict[ip]}")
        orgs += [(org, ip, ip_dict[ip])]
        if "Microsoft" in org:
            i+=1
            j+=ip_dict[ip]
        else:
            i+=1
            j+=ip_dict[ip]
            k+=1

        
    print(f'\nUnique click count: {i}')
    print(f'\nTotal click count: {j}')
    print(f'\nAdjusted Unique Click Count: {k}')
    return {'Unique Clicks':i, 'Total Clicks':j, 'Adjusted Clicks':k, 'orgs':orgs}


def slack(msg):
    requests.post(URL, json.dumps(msg))

def format_info(allinfo):
    uc = allinfo['Unique Clicks']
    tc = allinfo['Total Clicks']
    ac = allinfo['Adjusted Clicks']
    orgs = allinfo['orgs']
    orgstring = ''
    for org in orgs:
        orgstring += f'{org[0]} ({org[1]})\nClicks: {org[2]}\n\n'
    orgstring += f'Unique Clicks: {uc}\nTotal Clicks: {tc}\nAdjusted Clicks: {ac}'
    msg = {"text": orgstring}
    return msg

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Send auto click-count updates")
    parser.add_argument('-u', type=str, help='url to monitor for clicks', required=True)
    parser.add_argument('-t', type=int, help='Time (minutes) between full reports sent to slack, default 1hr', required=False)
    parser.add_argument('-r', type=str, help='Just generate clickcount report and exit', required=False)
    args = parser.parse_args()

    if args.t is not None:
        main(args.u, args.t)
    elif args.r is not None:
        main(args.u, report=True)
    else:
        main(args.u)
