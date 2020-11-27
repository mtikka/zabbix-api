#!/usr/bin/python3

# filename:      api.py
# purpose:       Zabbix api
# date/version:  27.11.2020
# author:        mtikka
# usage:         $ python3 api.py -h
#                $ ./api.py --help
# compatibility: Tested with Zabbix 5.2
# version notes: user.disconnect() added, password hidden from logs, input handler improved,
#                credentials taken from file by default, code tidied with linter

import csv
import datetime
import getpass
import http.client
import json
import logging
import platform
import smtplib
import sys
import urllib.request

from email.mime.text import MIMEText
from logging.handlers import RotatingFileHandler

# Functions
def addHosts(id):
    # Update groupdata from Zabbix server
    groupData, id = getHostgroup(id)

    # Get groupid for given template group
    templateData = {}

    # Get templates
    method = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {
            "output": [
                "templateid",
                "name"
            ]
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)
    id = (response['id'])

    for i in (response['result']):
        templateData[i.get('name')] = i.get('templateid')

    try:
        with open(hostlist, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=';')

            for row in csv_reader:
                try:
                    if row['hostname'].startswith('#'):
                        continue

                    groupIds = []
                    groupIds_tmp = []
                    templateIds = []
                    templateIds_tmp = []
                    interfaces = []
                    interface = row['interface']
                    host = row['hostname']
                    ipaddress = row['ipaddress']

                    for i in (row['groups']).split(','):
                        try:
                            # Create new group if it's missing from groupData
                            if not i in groupData.keys():
                                groupData, id = hostGroupCreate(groupData, i, id)

                            groupIds_tmp.extend([value for (key,value) in groupData.items() if i == key])
                        except:
                            continue

                    if len(groupIds_tmp) == 0:
                        logging.warning('addHosts: Host "' + host + '" cannot be without host group.')
                        continue

                    for i in groupIds_tmp:
                        groupIds.append({'groupid': i})

                    for i in (row['templates']).split(','):
                        # if 'SNMP' in i:
                        #     SNMPhost = True
                        try:
                            templateIds_tmp.extend([value for (key,value) in templateData.items() if i == key])
                        except:
                            continue
                except Exception as e:
                    logging.error('addHosts: Host "' + host + '" skipped. Ivalid row.')
                    continue

                for i in templateIds_tmp:
                    templateIds.append({'templateid': i})

                if interface == 'snmp' or interface == 'SNMP':
                    interfaces = [
                        {
                            "type": 2,
                            "main": 1,
                            "useip": 1,
                            "ip": ipaddress,
                            "dns": "",
                            "port": "161"
                        }
                    ]

                else:
                    interfaces = [
                        {
                            "type": 1,
                            "main": 1,
                            "useip": 1,
                            "ip": ipaddress,
                            "dns": "",
                            "port": "10050"
                        }
                    ]

                id = hostCreate(groupIds, host, interfaces, templateIds, id)

    except Exception as e:
        logging.fatal('addHosts: ' + str(e.args[1]) + ' (' + hostlist + ').')

    commDisconnect(1,id)

def checkInputs(operands):
    minSeverity = None
    to = None
    reportPeriod = None

    if helpRequest == True:
        printHelp()

    if 'getAuthKey' in operands:
        command = 'getAuthKey'
        operands.remove(command)

    elif 'createHostnameMacro' in operands:
        command = 'createHostnameMacro'
        operands.remove(command)

    elif 'updateHostnamesFromInventory' in operands:
        command = 'updateHostnamesFromInventory'
        operands.remove(command)

    elif 'smtpSwitchover' in operands:
        command = 'smtpSwitchover'
        operands.remove(command)

    elif 'addHosts' in operands:
        command = 'addHosts'
        operands.remove(command)

    elif 'problemReport' in operands:
        command = 'problemReport'
        operands.remove(command)

        minSeverity = options.get('minSeverity')
        if not minSeverity:
            minSeverity = '1'

        reportPeriod = options.get('reportPeriod')
        if not reportPeriod:
            reportPeriod = 'day'

        to = options.get('to')
        if (not reportPeriod == 'month' and not reportPeriod == 'week' and not reportPeriod == 'day') and to == None:
            logging.error('checkInputs: Report recipient missing (--to).')
            sys.exit(1)

    elif 'fixDiscoveredHostnames' in operands:
        command = 'fixDiscoveredHostnames'
        operands.remove(command)

    else:
        logging.error('checkInputs: Invalid command or command not defined.')
        sys.exit(1)

    if len(operands) > 0:
        ip = operands[0]
    else:
        logging.error('checkInputs: Zabbix server\'s address missing.')
        sys.exit(1)

    conn = options.get('conn')
    if conn == None or conn == 'urllib':
        conn = 'urllib'
    elif conn == 'httpclient':
        conn = 'httpclient'
    else:
        logging.error('checkInputs: Invalid connection method.')
        sys.exit(1)

    loglevel = options.get('loglevel')
    if loglevel == 'debug':
        ch.setLevel(logging.DEBUG)
    elif loglevel == 'info':
        ch.setLevel(logging.INFO)
    elif loglevel == 'warning':
        ch.setLevel(logging.WARNING)
    else:
        ch.setLevel(logging.INFO)

    hostlist = 'hostlist.txt'
    if 'hostlist' in options:
        hostlist = options.get('hostlist')

    return(command, conn, hostlist, minSeverity, ip, reportPeriod, to)

def commDisconnect(code,id):
    try:
        if authKey:
            userLogout(id)
    except:
        pass

    finally:
        if conn == 'httpclient':
            connection.close()
        sys.exit(code)

def commDisconnectContinue():
    if conn == 'httpclient':
        connection.close()

def commError(response):
    # e_code = None
    # e_message = None
    e_data = None

    try:
        # e_code = (response['error']['code'])
        # e_message = (response['error']['message'])
        e_data = (response['error']['data'])
    except:
        e_data = 'Can\'t get error description from response.'
    finally:
        # return(e_code, e_message, e_data)
        return(e_data)

def commErrorContinue(response):
    # e_code = None
    # e_message = None
    e_data = None

    try:
        # e_code = (response['error']['code'])
        # e_message = (response['error']['message'])
        e_data = (response['error']['data'])
    except:
        e_data = 'Can\'t get error description from response.'
    finally:
        id = (response['id'])
        # return(e_code, e_message, e_data, id)
        return(e_data, id)

def commHelper(method):
    if conn == 'urllib':
        response = commUrllib(method)
    elif conn == 'httpclient':
        response = commHttpClient(method)
    return(response)

def commHttpClient(method):
    try:
        connection.request('POST', url, json.dumps(method), headers)

    except Exception as e:
        #logging.fatal('commHttpClient: ' + str(e.args[1]) + '.')
        logging.fatal('commHttpClient: ' + str(e) + '.')
        #print('')
        commDisconnect(1,id)

    try:
        # Remove password from logs
        if len(method['params']) > 0:
            if 'password' in method['params'].keys():
                method['params']['password'] = '******'
        logging.debug('commHttpClient: ---> ---> ---> \n' + json.dumps(method, indent=4))
        # Get response, decode bytes to string, convert string to json
        response = json.loads(connection.getresponse().read().decode())
        logging.debug('commHttpClient: <--- <--- <--- \n' + json.dumps(response, indent=4))

        return(response)

    except Exception as e:
        logging.fatal('commHttpClient: ' + str(e) + '.')

    # finally:
        sys.exit(1)

def commUrllib(method):
    try:
        req = urllib.request.Request(url, json.dumps(method).encode(), headers)

        # Remove password from logs
        if len(method['params']) > 0:
            if 'password' in method['params'].keys():
                method['params']['password'] = '******'
        logging.debug('commUrllib: ---> ---> ---> \n' + json.dumps(method, indent=4))
        # Get response, decode bytes to string, convert string to json
        response = json.loads(urllib.request.urlopen(req).read().decode())
        logging.debug('commUrllib: <--- <--- <--- \n' + json.dumps(response, indent=4))
        return(response)

    except Exception as e:
        logging.fatal('commUrllib: ' + str(e) + '.')

        sys.exit(1)

def createHostnameMacro(id):

    # Get template name from user input
    template = options.get('t')
    if template == None:
        logging.error('createHostnameMacro: Template name missing (-t)' + '.')
        commDisconnect(1,id)

    macroName = '{$HOSTNAME}'

    # Get id number of given template
    method = {
            "jsonrpc": "2.0",
            "method": "template.get",
            "params": {
                "output": [
                    "templateid",
                    "name"],
                "filter": {
                    "host": [
                        template
                    ]
                }
            },
            "id": id + 1,
            "auth": authKey
            }

    response = commHelper(method)

    try:
        # Get template id and transaction id from response
        templateid = (response['result'][0]['templateid'])
        id = (response['id'])

    except:
        logging.error('createHostnameMacro: Template "' + template + '" does not exist on server.')
        commDisconnect(1,id)


    # Get hosts which are using the template
    method = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": [
                "hostid",
                "host"],
            "templateids": [
                templateid],
        },
        "id": id + 1,
        "auth": authKey
        }

    response = commHelper(method)

    # Get template id and transaction id from response
    hostList = (response['result'])
    id = (response['id'])

    if not hostList:
        logging.error('createHostnameMacro: Template "' + template + '" is not used by any host.')
        commDisconnect(1,id)

    # Add macro to all hosts which are using the given template
    for i in hostList:
        for j in i.keys():
            if j == 'hostid':
                hostId = i.get('hostid')
            elif j == 'host':
                fullHostName = i.get('host')

                if ' ' in fullHostName:
                    index = fullHostName.index(' ')
                    hostName = fullHostName[:index]
                else:
                    hostName = fullHostName

        method = {
                "jsonrpc": "2.0",
                "method": "usermacro.create",
                "params": {
                    "hostid": str(hostId),
                    "macro": macroName,
                    "value": str(hostName)
                },
                "id": id + 1,
                "auth": authKey
        }

        response = commHelper(method)

        try:
            # Check if response has valid data
            if response['result']['hostmacroids']:
                pass
            id = (response['id'])
            logging.info('createHostnameMacro: Macro "' + macroName + '" created succesfully to "' + fullHostName + '".')

        except:
            # e_code, e_message, e_data, id = commErrorContinue(response)
            e_data, id = commErrorContinue(response)
            #logging.info('createHostnameMacro: ' + e_data)
            id = (response['id'])

            if 'Macro \"{$HOSTNAME}\" already exists on' in e_data:
                # Update macro if it exist alredy

                # Get existing usermacroid
                method = {
                    "jsonrpc": "2.0",
                    "method": "usermacro.get",
                    "params": {
                        "hostids": str(hostId),
                        "filter" : {
                            "macro" : [
                                "{$HOSTNAME}"
                            ],
                        },
                    },
                    "id": id + 1,
                    "auth": authKey
                }

                response = commHelper(method)

                id = response['id']
                oldHostmacroid = response['result'][0]['hostmacroid']
                oldValue = response['result'][0]['value']

                if oldValue == str(hostName):
                    logging.info('createHostnameMacro: Macro "{$HOSTNAME}" with a valid value already exists on "' + fullHostName + '".')

                else:
                    method = {
                        "jsonrpc": "2.0",
                        "method": "usermacro.update",
                        "params": {
                            "hostmacroid": oldHostmacroid,
                            "value" : str(hostName)
                            },
                        "id": id + 1,
                        "auth": authKey
                    }

                    response = commHelper(method)

                    try:
                        # hostmacroid = (response['result']['hostmacroids'])
                        id = (response['id'])
                        logging.info('createHostnameMacro: Macro "' + macroName + '" updated succesfully to "' + fullHostName + '".')

                    except:
                        # e_code, e_message, e_data, id = commErrorContinue(response)
                        e_data, id = commErrorContinue(response)
                        logging.info('createHostnameMacro: ' + e_data)
                        id = (response['id'])

            else:
                logging.info('createHostnameMacro: ' + e_data)


    commDisconnect(0, id)

def credentialHandler(id):
    userfile = options.get('userfile')

    if not userfile:
        userfile = '.apiuser.txt'

    try:
        f = open(userfile, 'r')

        for i in f:
            # Get rid of linebreak characters
            i = i.replace('\n','')
            i = i.replace('\r','')

            # Extract username
            if 'username' in i and '=' in i:
                i = i.split('=')
                user = i[1]

            # Extract password
            elif 'password' in i and '=' in i:
                i = i.split('=')
                password = i[1]

        f.close()

    except:
        logging.warning('credentialHandler: Userfile "' + userfile + '" not found.')

        user = options.get('u')
        password = options.get('p')


    if conn == 'httpclient' and ( user == None or password == None ):
        commDisconnectContinue()
        id = 0

    if user == None:
        user = input('Username: ')

    if password == None:
        password = getpass.getpass()

    return(id, password, user)

def eventGet(id, timeEnd, timeStart):
    rEventData = {}

    method = {
        "jsonrpc": "2.0",
        "method": "event.get",
        "params": {
            "output": [
                "name",
                "clock",
                "severity",
                "r_eventid"
            ],
            "filter": {
                "source": "0",
                "object": "0",
            },
            "time_from": timeStart,
            #"time_till": timeEnd,
            #"select_acknowledges": "extend",
            #"selectTags": "extend",
            #"selectSuppressionData": "extend",
            #"objectids": "13926",
            "sortfield": ["clock", "eventid"],
            "sortorder": "DESC",
            "selectHosts": "true",
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)
    id = (response['id'])

    for i in (response['result'])[:]:

        # Remove events without host
        try:
            if not i['hosts']:
                response['result'].remove(i)
            else:
                # Move host information one level up
                i['hostid'] = i['hosts'][0]['hostid']
                i.pop('hosts', None)

            # Move events which has severity = 0 to another dict
            if i['severity'] == '0':
                rEventData[i['eventid']] = i['clock']
                response['result'].remove(i)

            # Remove low severity events
            elif int(i['severity']) < int(minSeverity):
                response['result'].remove(i)

            # Convert numerical value to string
            else:
                if i['severity'] == '1':
                    i['severity'] = 'Information'
                elif i['severity'] == '2':
                    i['severity'] = 'Warning'
                elif i['severity'] == '3':
                    i['severity'] = 'Average'
                elif i['severity'] == '4':
                    i['severity'] = 'High'
                elif i['severity'] == '5':
                    i['severity'] = 'Disaster'

            # Remove too new events
            if i['clock'] > timeEnd:
                response['result'].remove(i)
        except:
            continue

    eventData = response['result']

    return(eventData, id, rEventData)

def fixDiscoveredHostnames(id):
    hostsToBeRenamed = {}
    hostnamesFromList = {}

    # Get all hosts
    hosts, id = hostGet(id)

    for i in hosts:
        hostid = i['hostid']
        host = i['host']
        ip = i['interfaces'][0]['ip']

        if host == ip:
            # If hostname == ip-address, host will be renamed according to hostlist.txt.
            hostsToBeRenamed[ip] = hostid

    if len(hostsToBeRenamed) == 0:
        logging.info('fixDiscoveredHostnames: No altered hosts.')
        commDisconnect(0,id)

    try:
        with open(hostlist, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=';')

            for row in csv_reader:
                try:
                    if row['hostname'].startswith('#'):
                        continue

                    for i in hostsToBeRenamed:
                        if i in row['ipaddress']:
                            hostnamesFromList[row['ipaddress']] = row['hostname']

                except Exception as e:
                        logging.error('fixDiscoveredHostnames: Host "' + i + '" skipped. Ivalid row.')
                        continue

    except Exception as e:
        logging.fatal('fixDiscoveredHostnames: ' + str(e.args[1]) + ' (' + hostlist + ').')
        commDisconnect(1,id)

    for i in hostsToBeRenamed:
        hostid = hostsToBeRenamed.get(i)
        name = hostnamesFromList.get(i)
        if not name:
            logging.warning('fixDiscoveredHostnames: Host "' + i + '" not found from ' + hostlist + '.')
            continue

        method = {
                "jsonrpc": "2.0",
                "method": "host.update",
                "params": {
                    "hostid": hostid,
                    "host": name
                },
                "id": id + 1,
                "auth": authKey
                }

        response = commHelper(method)

        try:
            hostid = (response['result'].get('hostids'))
            id = (response['id'])
            logging.info('fixDiscoveredHostnames: Host "' + i + '" renamed to "' + name + '".')
        except:
            # e_code, e_message, e_data, id = commErrorContinue(response)
            e_data, id = commErrorContinue(response)
            logging.info('fixDiscoveredHostnames: ' + e_data)
            id = (response['id'])

    commDisconnect(0,id)

def getAuthKey(id):
    method = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": user,
            "password": password
        },
        "id": id + 1,
        "auth": None
    }

    response = commHelper(method)

    try:
        # Get authentication key and transaction id from response
        authKey = (response['result'])
        id = (response['id'])
        logging.info('getAuthKey: User "' + user + '" logged in.')
        return(authKey, id)
    except:
        # e_code, e_message, e_data = commError(response)
        e_data = commError(response)
        logging.error('getAuthKey: ' + e_data)
        commDisconnect(1,id)

def getHostgroup(id):
    # Get hostgroups from Zabbix server
    groupData = {}

    method = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {
            "output": [
                "name",
                "groupid"
            ],
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)
    id = (response['id'])

    for i in (response['result']):
        groupData[i.get('name')] = i.get('groupid')

    return(groupData, id)

def hostCreate(groupIds, host, interfaces, templateIds, id):
    method = {
    "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": host,
            "interfaces": interfaces,
            "groups": groupIds,
            "templates": templateIds,

            # "macros": [
            #     {
            #         "macro": "{$USER_ID}",
            #         "value": "123321"
            #     }
            # ],
            # "inventory_mode": 0,
            # "inventory": {
            #     "macaddress_a": "01234",
            #     "macaddress_b": "56768"
            # }
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)

    id = (response['id'])

    try:
        logging.info('hostCreate: Host "' + host + '" created with id ' + response['result']['hostids'][0] + '.')
    except:
        # e_code, e_message, e_data, id = commErrorContinue(response)
        e_data, id = commErrorContinue(response)
        logging.warning('hostCreate: ' + e_data)
        id = (response['id'])

    finally:
        return id

def hostGet(id):
    method={
    "jsonrpc": "2.0",
    "method": "host.get",
    "params": {
        "output": [
            "host"
            ],
        # "filter": {
        #     "host": [
        #         "My server"
        #     ]
        #},
        "selectInterfaces": [
            "type",
            "main",
            "useip",
            "ip",
            "dns",
            "port"
        ],
        "selectParentTemplates": [
            "templateid",
            "name"
            ],
    },
    "id": id + 1,
    "auth": authKey
    }

    response = commHelper(method)

    if len(response['result']) == 0:
        logging.error('hostGet: No hosts matching to query.')
        commDisconnect(1,id)

    id = (response['id'])

    return response['result'], id

def hostGroupCreate(groupData, groupName, id):
    method = {
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {
            "name": groupName
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)
    id = (response['id'])

    try:
        groupid = (response['result']['groupids'])
        groupData[groupName] = groupid[0]

    except:
        logging.error('hostGroupCreate: Failed to create new group "' + groupName + '".')

    logging.info('hostGroupCreate: Created new group "' + groupName + '".')

    return(groupData, id)

def inputHandler(optionsIn, optionsArg, optionsNoArg):
    helpRequest = False
    optionsOut = dict()
    operands = list()
    optionsOut['ihd'] = False

    if '-h' in optionsIn or '--help' in optionsIn or len(optionsIn) == 1:
        helpRequest = True
        return helpRequest, optionsOut, operands

    del optionsIn[0]

    for i in optionsIn[:]:
        if i.startswith('---'):
            logging.error('inputHandler: Option can not start with "---".')
            sys.exit(1)

        # Handle options and parameters separated with '='
        elif '=' in i:
            index = i.index('=')
            if i[:index] in optionsArg:
                optionsOut[i[:index].replace('-','')] = i[-(len(i)-index-1):]
                optionsIn.remove(i)

        # Handle long options
        elif i.startswith('--'):
            if i in optionsArg:
                # If next item is also option, exit
                if optionsIn[optionsIn.index(i)+1].startswith('-'):
                    logging.error('inputHandler: Option "' + i + '" has a bad argument "' + optionsIn[optionsIn.index(i)+1] + '".')
                    sys.exit(1)
                optionsOut[i.replace('-','')] = optionsIn[optionsIn.index(i)+1]
                index = optionsIn.index(i)
                del optionsIn[index:(index+2)]

            elif i in optionsNoArg or i == '--ihd':
                optionsIn.remove(i)
                i = i.replace('-','')
                optionsOut[i] = True

        # Handle short options and arguments typed together
        elif len(i) > 2:
            if i[:2] in optionsArg:
                optionsOut[i[:2].replace('-','')] = i[-(len(i)-2):]
                optionsIn.remove(i)

        # Handle short options with space
        elif i.startswith('-') and i in optionsArg:
            if optionsIn[optionsIn.index(i)+1].startswith('-'):
                logging.error('inputHandler: Option "' + i + '" has a bad argument "' + optionsIn[optionsIn.index(i)+1] + '".')
                sys.exit(1)
            optionsOut[i.replace('-','')] = optionsIn[optionsIn.index(i)+1]
            index = optionsIn.index(i)
            del optionsIn[index:(index+2)]

    # Second loop for commands/operands and options without arguments
    for i in optionsIn[:]:

        # Handle commands and operands
        if not i.startswith('-'):
            operands.append(i)
            optionsIn.remove(i)

        # Handle options without arguments
        if i.startswith('-'):
            for j in i:
                if j == '-':
                    continue

                elif j == 'h':
                    helpRequest = True
                    return helpRequest, optionsOut, operands

                elif '-'+j in optionsNoArg:
                        optionsOut[j] = True

    if optionsOut.pop('ihd') == True:
        print('inputHandler debug starts --->')
        print('Options given: \n' + json.dumps(optionsOut, indent=4))
        print('')
        print('Commands/Operands given: \n' + json.dumps(operands, indent=4))
        print('<--- inputHandler debug ends')
        print('')

    if len(optionsIn) > 0:
        logging.error('inputHandler: Unexpected option given: ' + optionsIn[0] + '.')
        sys.exit(1)

    return helpRequest, optionsOut, operands

def mediaTypeGet(id):
    method = {
        "jsonrpc": "2.0",
        "method": "mediatype.get",
        "params": {
            "output": [
                "description",
                "smtp_server",
                "smtp_email"
            ],
            "filter": {
                "type": "0",
                "status": "0"
            },
        },
        "id": id + 1,
        "auth": authKey
    }
    response = commHelper(method)
    id = (response['id'])

    if not response['result']:
        logging.error('mediaTypeGet: Can\'t get SMTP server information from Zabbix server.')
        commDisconnect(1,id)

    return(id, response['result'])

def printHelp():
    file = __file__.replace('./','')

    print('')
    print('Usage:')
    print('  (python3 ' + file  + ' | /' + file + ') <command> [options]... <Zabbix server IP>' )
    print('')
    print('Commands:')
    print('  addHosts                       Add hosts from csv-file.')
    print('                                 [--hostlist=<name of list>] [default: hostlist.txt].')
    print('  createHostnameMacro            Creates {$HOSTNAME} macro to all hosts which are using given template.')
    print('                                 -t=<template name>.')
    print('  fixDiscoveredHostnames         Renames hosts which has ip-address as hostname according to csv-file.')
    print('                                 [--hostlist=<name of list>] [default: hostlist.txt].')
    print('  getAuthKey                     Test communication and credentials.')
    print('  problemReport                  Generates a problem report and sends it by email.')
    print('                                 [--reportPeriod=<day|week|month|number_of_days>] [default: day]')
    print('                                 day, week and month settings gets receipients automatically from Zabbix user groups:')
    print('                                 Report_day, Report_week, Report_month.')
    print('                                 With custom timerange, recepients must be given as value of --to option.')
    print('                                 [--minSeverity=<1|2|3|4|5>] option defines lowest severity of shown problems. [Default: 1]' )
    print('                                 SMTP-server parameters are taken from Zabbix server\'s mediatypes.')
    print('  smtpSwitchover                 Changes users mediatype if failed mediatype is used.')
    print('                                 Mediatypes must be renamed as "Primary email" and')
    print('                                 "Secondary email".')
    print('  updateHostnamesFromInventory   Updates host names according to inventory name.')
    print('')
    print('Options:')
    print('  --conn (urllib | httpclient)   Connection method [default: urllib].')
    print('  -h --help                      Show this screen.')
    print('  --ihd                          Input handler debug.')
    print('  --loglevel=<debug | info | warning>')
    print('                                 Set the lowest level of displayed log messages [default: info].')
    print('  --logToFile                    Logging to file (/var/log/zabbix/api.log | c:\\temp\\api.log).')
    print('  -p password                    Password. Will be asked if not given or if userfile is not found.')
    print('  -u username                    Username. Will be asked if not given or if userfile is not found.')
    print('  --userfile=<filename>          Specifies file where username and pasword could be given. ')
    print('                                 [default: .apiuser.txt]')
    print('')
    sys.exit(0)

def problemGet(id):
    # This function uses event.get method because problem.get can't return hostname
    method = {
        "jsonrpc": "2.0",
        "method": "event.get",
        "params": {
            "output": [
                "name",
                "clock",
                "severity",
                "r_eventid",
                "acknowledged"
            ],
            "filter": {
                "severity": ["1", "2", "3", "4", "5"]
            },
            "sortfield": ["clock"],
            "sortorder": "DESC",
            "expandDescription": "true",
            "selectHosts": "true",

        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)
    id = (response['id'])

    for i in (response['result'])[:]:
        # Remove events which
        #  -does not have a hostname (maybe deleted)
        #  -does have severity 0 (recovery events etc.)
        #  -does have r_eventid (already recovered)
        if not i['hosts'] or i['severity'] == '0' or i['r_eventid'] != '0' or \
        int(i['severity']) < int(minSeverity):
            response['result'].remove(i)

        else:
            # Move host information one level up
            i['hostid'] = i['hosts'][0]['hostid']
            i.pop('hosts', None)

            if i['severity'] == '1':
                i['severity'] = 'Information'
            elif i['severity'] == '2':
                i['severity'] = 'Warning'
            elif i['severity'] == '3':
                i['severity'] = 'Average'
            elif i['severity'] == '4':
                i['severity'] = 'High'
            elif i['severity'] == '5':
                i['severity'] = 'Disaster'


    problemData = response['result']

    return(id, problemData)

def problemReport(id):

    timeNow = datetime.datetime.now().timestamp()

    # Get userGroupData for reporting groups
    id, userGroupData = userGroupGet(id, "Report*")

    # Get SMTP servers from Zabbix server
    id, smtpServers = mediaTypeGet(id)

    # Get users from Zabbix server
    id, userData = userGet(id)

    # Get hostids and hostnames
    hosts, id = hostGet(id)
    hostData = {}
    for i in hosts:
        hostData[i['hostid']] = i['host']

    def getReportEmails(reportPeriod):
        receiver = ''
        for i in userGroupData:
            if reportPeriod in i['name']:
                for j in i['users']:
                    for k in userData:
                        if j['userid'] == k['userid']:
                            for l in k['medias']:
                                for m in l['sendto']:
                                    #reportEmails.append(m)
                                    receiver += m + ','
        receiver = receiver[:-1]
        if receiver == '':
            logging.error('getReportEmails: Receiver list is empty.')
            commDisconnect(1,id)

        return receiver

    today = datetime.date.today()

    if reportPeriod == 'month':
        subject = 'Monthly'
        receiver = getReportEmails(reportPeriod)

        startOfThisMonth = today.replace(day=1)
        lastDayOfPrevMonth = startOfThisMonth - datetime.timedelta(days=1)
        startOfPrevMonth = lastDayOfPrevMonth.replace(day=1)

        timeStart = startOfPrevMonth.strftime('%s')
        timeEnd = startOfThisMonth.strftime('%s')


    elif reportPeriod == 'week':
        subject = 'Weekly'
        receiver = getReportEmails(reportPeriod)

        startOfThisWeek = today - datetime.timedelta(days=today.weekday())
        startOfPrevWeek = startOfThisWeek - datetime.timedelta(days=7)

        timeStart = startOfPrevWeek.strftime('%s')
        timeEnd = startOfThisWeek.strftime('%s')


    elif reportPeriod == 'day':
        subject = 'Daily'
        receiver = getReportEmails(reportPeriod)

        prevDay = today - datetime.timedelta(days=1)

        timeStart = prevDay.strftime('%s')
        timeEnd = today.strftime('%s')

    else:
        subject = 'Custom'
        receiver = to

        timeEnd = timeNow
        timeStart = timeEnd - int(reportPeriod) * 24 * 60 * 60

    # Get events
    eventData, id, rEventData = eventGet(id, timeEnd, timeStart)

    # Get active problems
    id, problemData = problemGet(id)

    messageBody = '<html><body>'
    messageBody += '<h2>Active Problems</h2>'

    if len(problemData) == 0:
        messageBody += 'Nothing to report.</h2><br><br>'

    else:
        messageBody += '<table border="1" cellpadding="5">'
        messageBody += '<th>Event time</th>'
        messageBody += '<th>Duration</th>'
        messageBody += '<th>Host</th>'
        messageBody += '<th>Trigger</th>'
        messageBody += '<th>Severity</th>'

        for i in problemData:
            host = hostData.get(i['hostid'])

            duration = str(datetime.timedelta(seconds=(int(timeNow) - int(i['clock']))))

            messageBody += '<tr>'
            messageBody += '<td>' + datetime.datetime.fromtimestamp(int(i['clock'])).strftime("%d.%m.%Y %H:%M:%S") + '</td>'
            messageBody += '<td>' + duration + '</td>'
            messageBody += '<td>' + host + '</td>'
            messageBody += '<td>' + i['name'] + '</td>'
            messageBody += '<td>' + i['severity'] + '</td>'
            messageBody += '</tr>'

        messageBody += '</table>'
        messageBody += '<br>'
        messageBody += '<br>'

    messageBody += '<h2>' + subject + ' report</h2>'
    messageBody += '<h4>' + datetime.datetime.fromtimestamp(int(timeStart)).strftime("%d.%m.%Y %H:%M:%S") + ' - ' + \
        datetime.datetime.fromtimestamp(int(timeEnd)).strftime("%d.%m.%Y %H:%M:%S") + '</h4>'

    if len(eventData) == 0:
        messageBody += 'Nothing to report.<br><br>'

    else:
        messageBody += '<table border="1" cellpadding="5">'
        messageBody += '<th>Event time</th>'
        messageBody += '<th>Recovery time</th>'
        messageBody += '<th>Duration</th>'
        messageBody += '<th>Host</th>'
        messageBody += '<th>Trigger</th>'
        messageBody += '<th>Severity</th>'


        for i in (eventData):
            host = hostData.get(i['hostid'])

            recoveryTime = rEventData.get(i['r_eventid'])

            if recoveryTime:
                duration = str(datetime.timedelta(seconds=(int(recoveryTime) - int(i['clock']))))
            else:
                duration = str(datetime.timedelta(seconds=(int(timeNow) - int(i['clock']))))

            # Convert recovery time to localtime
            try:
                recoveryTime = datetime.datetime.fromtimestamp(int(recoveryTime)).strftime("%d.%m.%Y %H:%M:%S")
            except:
                recoveryTime = ''

            messageBody += '<tr>'
            messageBody += '<td>' + datetime.datetime.fromtimestamp(int(i['clock'])).strftime("%d.%m.%Y %H:%M:%S") + '</td>'
            messageBody += '<td>' + recoveryTime + '</td>'
            messageBody += '<td>' + duration + '</td>'
            messageBody += '<td>' + host + '</td>'
            messageBody += '<td>' + i['name'] + '</td>'
            messageBody += '<td>' + i['severity'] + '</td>'
            messageBody += '</tr>'

        messageBody += '</table>'
        messageBody += '<br>'

    messageBody += 'Report generated at ' + datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    messageBody += '<br>'
    if minSeverity == '1':
        messageBody += 'Lowest severity = Information'
    elif minSeverity == '2':
        messageBody += 'Lowest severity = Warning'
    elif minSeverity == '3':
        messageBody += 'Lowest severity = Average'
    elif minSeverity == '4':
        messageBody += 'Lowest severity = High'
    elif minSeverity == '5':
        messageBody += 'Lowest severity = Disaster'

    messageBody += '</body>'
    messageBody += '</html>'

    message = MIMEText(messageBody, 'html', 'utf-8')

    message['Subject'] = subject + ' report'
    message['To'] = receiver

    receiverList = receiver.split(',')

    failedSmtpCount = 0

    for i in smtpServers:
        try:
            server = smtplib.SMTP(i['smtp_server'])
            # Test connection to server. If fails try next server.
            server.noop()

            # Send mail after succesfull test.
            message['From'] = i['smtp_email']
            #server.debuglevel=1
            server.sendmail(i['smtp_email'], receiverList, message.as_string())
            server.quit()
            logging.info('problemReport: Report sent via ' + i['smtp_server'] + '.')
            commDisconnect(0,id)

        except Exception as e:
            logging.warning('problemReport: Can\'t send report via ' + i['smtp_server'] + '. ' + str(e) + '.')
            failedSmtpCount += 1

        finally:
            if failedSmtpCount == len(smtpServers):
                logging.error('problemReport: Can\'t send report. All smtp servers failed.')

    commDisconnect(0, id)

def smtpSwitchover(id):
    primaryFailed = False
    secondaryFailed = False
    primaryMediatypeId = None
    secondaryMediatypeId = None

    # Get mediatypeids
    method = {
        "jsonrpc": "2.0",
        "method": "mediatype.get",
        "params": {
            "output": [
                "description"
            ],
            "filter": {
                "type": "0",
                "status": "0"
            },
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)

    id = (response['id'])

    for i in response['result']:
        if 'Primary' in i.get('description') or 'primary' in i.get('description'):
            primaryMediatypeId = i.get('mediatypeid')
        elif 'Secondary' in i.get('description') or 'secondary' in i.get('description'):
            secondaryMediatypeId = i.get('mediatypeid')

    if not primaryMediatypeId:
        logging.error('smtpSwitchover: Primary Email -mediatype does not exist or it is disabled.')

    if not secondaryMediatypeId:
        logging.error('smtpSwitchover: Secondary Email -mediatype does not exist or it is disabled.')

    if not primaryMediatypeId or not secondaryMediatypeId:
        commDisconnect(1,id)

    # Get SMTP servers' triggers
    method = {
        "jsonrpc": "2.0",
        "method": "trigger.get",
        "params": {
            "group": "SMTP servers",
            "selectHosts": [
                "name"
            ],
            "output": [
                "value"
            ],
            "filter": {
                "value": 1
            }
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)

    id = (response['id'])

    for i in response['result']:
        value = i.get('value')
        if value == '1':
            name = i['hosts'][0].get('name')
            if 'primary' in name or 'Primary' in name:
                primaryFailed = True
            elif 'secondary' in name or 'Secondary' in name:
                secondaryFailed = True
            logging.warning('smtpSwitchover: '+ name + ' failed.')

    if primaryFailed == False and secondaryFailed == False:
        logging.info('smtpSwitchover: Both servers ok, no need to do switchover.')
        commDisconnect(0,id)
    elif primaryFailed == True and secondaryFailed == True:
        commDisconnect(0,id)


    userid = None
    # alias = NotImplemented
    # userMediatypeid = None
    # sendto = None

    id, userData = userGet(id)

    # Loop through users
    for i in userData:
        needToUpdate = False

        alias = i.get('alias')
        userid = i.get('userid')
        medias = i['medias']

        # Loop through user's medias
        for j in medias:
            if j['mediatypeid'] == primaryMediatypeId and primaryFailed == True:
                j['mediatypeid'] = secondaryMediatypeId
                needToUpdate = True
            elif j['mediatypeid'] == secondaryMediatypeId and secondaryFailed == True:
                j['mediatypeid'] = primaryMediatypeId
                needToUpdate = True
            else:
                continue

        if needToUpdate == True:
            method = {
                "jsonrpc": "2.0",
                "method": "user.update",
                "params": {
                    "userid": userid,
                    "user_medias": medias,
                },
                "id": id + 1,
                "auth": authKey
            }

            response = commHelper(method)

            id = (response['id'])

            try:
                # hostid = (response['result'].get('userids'))
                id = (response['id'])
                if j['mediatypeid'] == primaryMediatypeId:
                    logging.info('smtpSwitchover: ' + alias + '\'s mediatype(s) changed.')
                elif j['mediatypeid'] == secondaryMediatypeId:
                    logging.info('smtpSwitchover: ' + alias + '\'s mediatype(s) changed.')

            except:
                commErrorContinue(response)
                id = (response['id'])
        else:
            logging.debug('smtpSwitchover: '+ alias + '\'s mediatype(s) ok.')

    commDisconnect(0,id)

def updateHostnamesFromInventory(id):
    method = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": [
                "host"
            ],
            "selectInventory": [
                "name",
            ],
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)

    id = (response['id'])

    for i in response['result']:
        hostid = i.get('hostid')
        host = i.get('host')
        if len(i['inventory']) != 0:
            name = i['inventory'].get('name')
        else:
            continue

        if name == '':
            logging.info('updateHostnamesFromInventory: Host "' + host + '" skipped. Inventory name is empty.')

        elif host != name:
            method = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {
                "hostid": hostid,
                "host": name
            },
            "id": id + 1,
            "auth": authKey
            }

            response = commHelper(method)

            try:
                hostid = (response['result'].get('hostids'))
                id = (response['id'])
                logging.info('updateHostnamesFromInventory: Host "' + host + '" renamed to "' + name + '".')
            except:
                # e_code, e_message, e_data, id = commErrorContinue(response)
                e_data, id = commErrorContinue(response)
                logging.info('createHostnameMacro: ' + e_data)
                id = (response['id'])

        else:
            logging.info('updateHostnamesFromInventory: Host "' + host + '" skipped. Hostname matches to inventory name.')

    commDisconnect(0, id)

def userGet(id):

    method = {
        "jsonrpc": "2.0",
        "method": "user.get",
        "params": {
            "output": [
                "alias",
                "userid"
            ],
            "selectMedias" : [
                "sendto",
                "mediatypeid"
            ]
        },
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)
    id = (response['id'])

    # Remove users without medias
    for i in response['result'][:]:
        if len(i['medias']) == 0:
            response['result'].remove(i)

    if len(response['result']) == 0:
        logging.error('userGet: Can\'t get any users from Zabbix server.')
        commDisconnect(1,id)

    return(id, response['result'])

def userGroupGet(id, groupNameKey):
    method = {
        "jsonrpc": "2.0",
        "method": "usergroup.get",
        "params": {
            "output": [
                "name"
            ],
            "status": 0,
            "search": {
                "name": groupNameKey
            },
            "searchWildcardsEnabled": "true",
            "selectUsers" : [
                "alias",
                "userid"
            ]
        },
        "id": id + 1,
        "auth": authKey
    }
    response = commHelper(method)
    id = (response['id'])

    userGroupData = response['result']

    if len(userGroupData) > 0:
        return(id, userGroupData)
    else:
        logging.error('userGroupGet: Search key "'+ groupNameKey + '" does not match any group.')
        commDisconnect(0,id)

def userLogout(id):
    method = {
        "jsonrpc": "2.0",
        "method": "user.logout",
        "params": [],
        "id": id + 1,
        "auth": authKey
    }

    response = commHelper(method)

    try:
        if response['result']:
            logging.info('userLogout: User "' + user + '" logged out.')
    except:
        # e_code, e_message, e_data = commError(response)
        e_data = commError(response)
        logging.error('userLogout: ' + e_data)
        #commDisconnect(1,id)

def testCommunication():

    method = {
        "jsonrpc": "2.0",
        "method": "apiinfo.version",
        "params": [],
        "id": 1
    }

    response = commHelper(method)

    try:
        #version = (response['result'])
        id = (response['id'])
        logging.info('testCommunication: Connected to Zabbix server on ' + ip + ' with ' + conn + '.')
        #logging.info('testCommunication: Server version: ' + version + '.')
        return(id)

    except:
        logging.error('testCommunication: Can\'t connect to Zabbix server')
        commDisconnect(1,id)


# Create logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')

# Create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)

# Get user given options
arg0 = sys.argv[0] # Needed for VSCode debugging
helpRequest, options, operands = inputHandler( \
    sys.argv, \
    ['-u', '-p', '-t', '--conn', '--loglevel', '--hostlist', '--minSeverity', '--to', '--reportPeriod', '--userfile'], \
    ['--logToFile'])
sys.argv.append(arg0) # Needed for VSCode debugging

# Set logging to file
if 'logToFile' in options:
    # Create file handler and set level to INFO
    try:
        if platform.system() == 'Linux':
            fh = logging.handlers.RotatingFileHandler('/var/log/zabbix/api.log', maxBytes = 1024*1024*5, backupCount = 9)
        else:
            fh = logging.handlers.RotatingFileHandler('c:\\temp\\api.log', maxBytes = 1024*1024*5, backupCount = 9)
        fh.setLevel(logging.INFO)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    except:
        logging.warning('api.py: Can\'t redirect log to file. Skipping --logToFile option.')

# Check inputs
command, conn, hostlist, minSeverity, ip, reportPeriod, to = checkInputs(operands)

# # # Variables # # #

headers = {'Content-type':'application/json'}
url = 'http://' + ip + '/zabbix/api_jsonrpc.php'


if conn == 'httpclient':
    connection = http.client.HTTPConnection(ip, timeout=10)
else:
    connection = None


# # # Main program # # #

# Test communication to Zabbix server
id = testCommunication()

# Credentials
id, password, user = credentialHandler(id)

# Get authentication key
authKey, id = getAuthKey(id)

# Run selected command
if command == 'createHostnameMacro':
    createHostnameMacro(id)
elif command == 'updateHostnamesFromInventory':
    updateHostnamesFromInventory(id)
elif command == 'smtpSwitchover':
    smtpSwitchover(id)
elif command == 'addHosts':
    addHosts(id)
elif command == 'problemReport':
    problemReport(id)
elif command == 'fixDiscoveredHostnames':
    fixDiscoveredHostnames(id)

# userLogout(id)

commDisconnect(0,id)

# EOF