# -*- coding: utf-8 -*-
from random import randint

from django.shortcuts import render, redirect
from django.http import HttpResponse
from plogical.getSystemInformation import SystemInformation
import json
from loginSystem.views import loadLoginPage
from .models import version
import requests
import subprocess
import shlex
import os
import plogical.CyberCPLogFileWriter as logging
from plogical.acl import ACLManager
from manageServices.models import PDNSStatus
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from plogical.processUtilities import ProcessUtilities
from plogical.httpProc import httpProc
from websiteFunctions.models import Websites, WPSites
from databases.models import Databases
from mailServer.models import EUsers
from ftp.models import Users as FTPUsers
from loginSystem.models import Administrator
from django.views.decorators.http import require_GET, require_POST
import pwd

# Create your views here.

VERSION = '2.4'
BUILD = 3


@ensure_csrf_cookie
def renderBase(request):
    template = 'baseTemplate/homePage.html'
    cpuRamDisk = SystemInformation.cpuRamDisk()
    finaData = {'ramUsage': cpuRamDisk['ramUsage'], 'cpuUsage': cpuRamDisk['cpuUsage'],
                'diskUsage': cpuRamDisk['diskUsage']}
    proc = httpProc(request, template, finaData)
    return proc.render()


@ensure_csrf_cookie
def versionManagement(request):
    getVersion = requests.get('https://cyberpanel.net/version.txt')
    latest = getVersion.json()
    latestVersion = latest['version']
    latestBuild = latest['build']

    currentVersion = VERSION
    currentBuild = str(BUILD)

    u = "https://api.github.com/repos/usmannasir/cyberpanel/commits?sha=v%s.%s" % (latestVersion, latestBuild)
    logging.writeToFile(u)
    r = requests.get(u)
    latestcomit = r.json()[0]['sha']

    command = "git -C /usr/local/CyberCP/ rev-parse HEAD"
    output = ProcessUtilities.outputExecutioner(command)

    Currentcomt = output.rstrip("\n")
    notechk = True

    if Currentcomt == latestcomit:
        notechk = False

    template = 'baseTemplate/versionManagment.html'
    finalData = {'build': currentBuild, 'currentVersion': currentVersion, 'latestVersion': latestVersion,
                 'latestBuild': latestBuild, 'latestcomit': latestcomit, "Currentcomt": Currentcomt,
                 "Notecheck": notechk}

    proc = httpProc(request, template, finalData, 'versionManagement')
    return proc.render()


@ensure_csrf_cookie
def upgrade_cyberpanel(request):
    if request.method == 'POST':
        try:
            upgrade_command = 'sh <(curl https://raw.githubusercontent.com/usmannasir/cyberpanel/stable/preUpgrade.sh || wget -O - https://raw.githubusercontent.com/usmannasir/cyberpanel/stable/preUpgrade.sh)'
            result = subprocess.run(upgrade_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True)

            if result.returncode == 0:
                response_data = {'success': True, 'message': 'CyberPanel upgrade completed successfully.'}
            else:
                response_data = {'success': False,
                                 'message': 'CyberPanel upgrade failed. Error output: ' + result.stderr}
        except Exception as e:
            response_data = {'success': False, 'message': 'An error occurred during the upgrade: ' + str(e)}


def getAdminStatus(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)

        if os.path.exists('/home/cyberpanel/postfix'):
            currentACL['emailAsWhole'] = 1
        else:
            currentACL['emailAsWhole'] = 0

        if os.path.exists('/home/cyberpanel/pureftpd'):
            currentACL['ftpAsWhole'] = 1
        else:
            currentACL['ftpAsWhole'] = 0

        try:
            pdns = PDNSStatus.objects.get(pk=1)
            currentACL['dnsAsWhole'] = pdns.serverStatus
        except:
            if ProcessUtilities.decideDistro() == ProcessUtilities.ubuntu or ProcessUtilities.decideDistro() == ProcessUtilities.ubuntu20:
                pdnsPath = '/etc/powerdns'
            else:
                pdnsPath = '/etc/pdns'

            if os.path.exists(pdnsPath):
                PDNSStatus(serverStatus=1).save()
                currentACL['dnsAsWhole'] = 1
            else:
                currentACL['dnsAsWhole'] = 0

        json_data = json.dumps(currentACL)
        return HttpResponse(json_data)
    except KeyError:
        return HttpResponse("Can not get admin Status")


def getSystemStatus(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        
        # Only admins should see system-wide information
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'status': 0, 'error_message': 'Admin access required'}), content_type='application/json', status=403)
        
        HTTPData = SystemInformation.getSystemInformation()
        json_data = json.dumps(HTTPData)
        return HttpResponse(json_data)
    except KeyError:
        return HttpResponse("Can not get admin Status")


def getLoadAverage(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        
        # Only admins should see system load averages
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'status': 0, 'error_message': 'Admin access required'}), content_type='application/json', status=403)
        
        loadAverage = SystemInformation.cpuLoad()
        loadAverage = list(loadAverage)
        one = loadAverage[0]
        two = loadAverage[1]
        three = loadAverage[2]
        loadAvg = {"one": one, "two": two, "three": three}
        json_data = json.dumps(loadAvg)
        return HttpResponse(json_data)
    except KeyError:
        return HttpResponse("Not allowed.")


@ensure_csrf_cookie
def versionManagment(request):
    ## Get latest version

    getVersion = requests.get('https://cyberpanel.net/version.txt')
    latest = getVersion.json()
    latestVersion = latest['version']
    latestBuild = latest['build']

    ## Get local version

    currentVersion = VERSION
    currentBuild = str(BUILD)

    u = "https://api.github.com/repos/usmannasir/cyberpanel/commits?sha=v%s.%s" % (latestVersion, latestBuild)
    logging.CyberCPLogFileWriter.writeToFile(u)
    r = requests.get(u)
    latestcomit = r.json()[0]['sha']

    command = "git -C /usr/local/CyberCP/ rev-parse HEAD"
    output = ProcessUtilities.outputExecutioner(command)

    Currentcomt = output.rstrip("\n")
    notechk = True

    if (Currentcomt == latestcomit):
        notechk = False

    template = 'baseTemplate/versionManagment.html'
    finalData = {'build': currentBuild, 'currentVersion': currentVersion, 'latestVersion': latestVersion,
                 'latestBuild': latestBuild, 'latestcomit': latestcomit, "Currentcomt": Currentcomt,
                 "Notecheck": notechk}

    proc = httpProc(request, template, finalData, 'versionManagement')
    return proc.render()


def upgrade(request):
    try:
        admin = request.session['userID']
        currentACL = ACLManager.loadedACL(admin)

        data = json.loads(request.body)

        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadErrorJson('fetchStatus', 0)

        from plogical.applicationInstaller import ApplicationInstaller

        extraArgs = {}
        extraArgs['branchSelect'] = data["branchSelect"]
        background = ApplicationInstaller('UpgradeCP', extraArgs)
        background.start()

        adminData = {"upgrade": 1}
        json_data = json.dumps(adminData)
        return HttpResponse(json_data)

    except KeyError:
        adminData = {"upgrade": 1, "error_message": "Please login or refresh this page."}
        json_data = json.dumps(adminData)
        return HttpResponse(json_data)


def upgradeStatus(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadErrorJson('FilemanagerAdmin', 0)

        try:
            if request.method == 'POST':
                from plogical.upgrade import Upgrade

                path = Upgrade.LogPathNew

                try:
                    upgradeLog = ProcessUtilities.outputExecutioner(f'cat {path}')
                except:
                    final_json = json.dumps({'finished': 0, 'upgradeStatus': 1,
                                             'error_message': "None",
                                             'upgradeLog': "Upgrade Just started.."})
                    return HttpResponse(final_json)

                if upgradeLog.find("Upgrade Completed") > -1:

                    command = f'rm -rf {path}'
                    ProcessUtilities.executioner(command)

                    final_json = json.dumps({'finished': 1, 'upgradeStatus': 1,
                                             'error_message': "None",
                                             'upgradeLog': upgradeLog})
                    return HttpResponse(final_json)
                else:
                    final_json = json.dumps({'finished': 0, 'upgradeStatus': 1,
                                             'error_message': "None",
                                             'upgradeLog': upgradeLog})
                    return HttpResponse(final_json)
        except BaseException as msg:
            final_dic = {'upgradeStatus': 0, 'error_message': str(msg)}
            final_json = json.dumps(final_dic)
            return HttpResponse(final_json)
    except KeyError:
        final_dic = {'upgradeStatus': 0, 'error_message': "Not Logged In, please refresh the page or login again."}
        final_json = json.dumps(final_dic)
        return HttpResponse(final_json)


def upgradeVersion(request):
    try:

        vers = version.objects.get(pk=1)
        getVersion = requests.get('https://cyberpanel.net/version.txt')
        latest = getVersion.json()
        vers.currentVersion = latest['version']
        vers.build = latest['build']
        vers.save()
        return HttpResponse("Version upgrade OK.")
    except BaseException as msg:
        logging.CyberCPLogFileWriter.writeToFile(str(msg))
        return HttpResponse(str(msg))


@ensure_csrf_cookie
def design(request):
    ### Load Custom CSS
    try:
        from baseTemplate.models import CyberPanelCosmetic
        cosmetic = CyberPanelCosmetic.objects.get(pk=1)
    except:
        from baseTemplate.models import CyberPanelCosmetic
        cosmetic = CyberPanelCosmetic()
        cosmetic.save()

    val = request.session['userID']
    currentACL = ACLManager.loadedACL(val)
    if currentACL['admin'] == 1:
        pass
    else:
        return ACLManager.loadErrorJson('reboot', 0)

    finalData = {}

    if request.method == 'POST':
        MainDashboardCSS = request.POST.get('MainDashboardCSS', '')
        cosmetic.MainDashboardCSS = MainDashboardCSS
        cosmetic.save()
        finalData['saved'] = 1

    ####### Fetch sha...

    sha_url = "https://api.github.com/repos/usmannasir/CyberPanel-Themes/commits"

    sha_res = requests.get(sha_url)

    sha = sha_res.json()[0]['sha']

    l = "https://api.github.com/repos/usmannasir/CyberPanel-Themes/git/trees/%s" % sha
    fres = requests.get(l)
    tott = len(fres.json()['tree'])
    finalData['tree'] = []
    for i in range(tott):
        if (fres.json()['tree'][i]['type'] == "tree"):
            finalData['tree'].append(fres.json()['tree'][i]['path'])

    template = 'baseTemplate/design.html'
    finalData['cosmetic'] = cosmetic

    proc = httpProc(request, template, finalData, 'versionManagement')
    return proc.render()


def getthemedata(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        data = json.loads(request.body)

        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadErrorJson('reboot', 0)

        # logging.CyberCPLogFileWriter.writeToFile(str(data) + "  [themedata]")

        url = "https://raw.githubusercontent.com/usmannasir/CyberPanel-Themes/main/%s/design.css" % data['Themename']

        res = requests.get(url)

        rsult = res.text
        final_dic = {'status': 1, 'csscontent': rsult}
        final_json = json.dumps(final_dic)
        return HttpResponse(final_json)
    except BaseException as msg:
        final_dic = {'status': 0, 'error_message': str(msg)}
        final_json = json.dumps(final_dic)
        return HttpResponse(final_json)


def onboarding(request):
    template = 'baseTemplate/onboarding.html'

    proc = httpProc(request, template, None, 'admin')
    return proc.render()


def runonboarding(request):
    try:
        userID = request.session['userID']
        currentACL = ACLManager.loadedACL(userID)

        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadErrorJson()

        data = json.loads(request.body)
        hostname = data['hostname']

        try:
            rDNSCheck = str(int(data['rDNSCheck']))
        except:
            rDNSCheck = 0

        tempStatusPath = "/home/cyberpanel/" + str(randint(1000, 9999))

        WriteToFile = open(tempStatusPath, 'w')
        WriteToFile.write('Starting')
        WriteToFile.close()

        command = f'/usr/local/CyberCP/bin/python /usr/local/CyberCP/plogical/virtualHostUtilities.py OnBoardingHostName --virtualHostName {hostname} --path {tempStatusPath} --rdns {rDNSCheck}'
        ProcessUtilities.popenExecutioner(command)

        dic = {'status': 1, 'tempStatusPath': tempStatusPath}
        json_data = json.dumps(dic)
        return HttpResponse(json_data)


    except BaseException as msg:
        dic = {'status': 0, 'error_message': str(msg)}
        json_data = json.dumps(dic)
        return HttpResponse(json_data)

def RestartCyberPanel(request):
    try:
        userID = request.session['userID']
        currentACL = ACLManager.loadedACL(userID)

        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadErrorJson()


        command = 'systemctl restart lscpd'
        ProcessUtilities.popenExecutioner(command)

        dic = {'status': 1}
        json_data = json.dumps(dic)
        return HttpResponse(json_data)


    except BaseException as msg:
        dic = {'status': 0, 'error_message': str(msg)}
        json_data = json.dumps(dic)
        return HttpResponse(json_data)

def getDashboardStats(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        admin = Administrator.objects.get(pk=val)
        
        # Check if user is admin
        if currentACL['admin'] == 1:
            # Admin can see all resources
            total_users = Administrator.objects.count()
            total_sites = Websites.objects.count()
            total_wp_sites = WPSites.objects.count()
            total_dbs = Databases.objects.count()
            total_emails = EUsers.objects.count()
            total_ftp_users = FTPUsers.objects.count()
        else:
            # Non-admin users can only see their own resources and resources of users they created
            
            # Count users created by this admin (resellers)
            total_users = Administrator.objects.filter(owner=admin.pk).count() + 1  # +1 for self
            
            # Get websites directly owned by this admin
            user_websites = admin.websites_set.all()
            website_names = list(user_websites.values_list('domain', flat=True))
            
            # Also get websites owned by admins created by this user (reseller pattern)
            child_admins = Administrator.objects.filter(owner=admin.pk)
            for child_admin in child_admins:
                child_websites = child_admin.websites_set.all()
                website_names.extend(list(child_websites.values_list('domain', flat=True)))
            
            total_sites = len(website_names)
            
            # Count WP sites associated with user's websites
            if website_names:
                total_wp_sites = WPSites.objects.filter(owner__domain__in=website_names).count()
                
                # Count databases associated with user's websites
                total_dbs = Databases.objects.filter(website__domain__in=website_names).count()
                
                # Count email accounts associated with user's domains
                from mailServer.models import Domains as EmailDomains
                total_emails = EUsers.objects.filter(emailOwner__domainOwner__domain__in=website_names).count()
                
                # Count FTP users associated with user's domains
                total_ftp_users = FTPUsers.objects.filter(domain__in=website_names).count()
            else:
                total_wp_sites = 0
                total_dbs = 0
                total_emails = 0
                total_ftp_users = 0
        
        data = {
            'total_users': total_users,
            'total_sites': total_sites,
            'total_wp_sites': total_wp_sites,
            'total_dbs': total_dbs,
            'total_emails': total_emails,
            'total_ftp_users': total_ftp_users,
            'status': 1
        }
        return HttpResponse(json.dumps(data), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'status': 0, 'error_message': str(e)}), content_type='application/json')

def getTrafficStats(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        
        # Only admins should see system-wide network stats
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'status': 0, 'error_message': 'Admin access required', 'admin_only': True}), content_type='application/json')
        
        # Get network stats from /proc/net/dev (Linux)
        rx = tx = 0
        with open('/proc/net/dev', 'r') as f:
            for line in f.readlines():
                if 'lo:' in line:
                    continue
                if ':' in line:
                    parts = line.split()
                    rx += int(parts[1])
                    tx += int(parts[9])
        data = {
            'rx_bytes': rx,
            'tx_bytes': tx,
            'status': 1
        }
        return HttpResponse(json.dumps(data), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'status': 0, 'error_message': str(e)}), content_type='application/json')

def getDiskIOStats(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        
        # Only admins should see system-wide disk I/O stats
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'status': 0, 'error_message': 'Admin access required', 'admin_only': True}), content_type='application/json')
        
        # Parse /proc/diskstats for all disks
        read_sectors = 0
        write_sectors = 0
        sector_size = 512  # Most Linux systems use 512 bytes per sector
        with open('/proc/diskstats', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 14:
                    continue
                # parts[2] is device name, skip loopback/ram devices
                dev = parts[2]
                if dev.startswith('loop') or dev.startswith('ram'):
                    continue
                # 6th and 10th columns: sectors read/written
                read_sectors += int(parts[5])
                write_sectors += int(parts[9])
        data = {
            'read_bytes': read_sectors * sector_size,
            'write_bytes': write_sectors * sector_size,
            'status': 1
        }
        return HttpResponse(json.dumps(data), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'status': 0, 'error_message': str(e)}), content_type='application/json')

def getCPULoadGraph(request):
    try:
        val = request.session['userID']
        currentACL = ACLManager.loadedACL(val)
        
        # Only admins should see system-wide CPU stats
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'status': 0, 'error_message': 'Admin access required', 'admin_only': True}), content_type='application/json')
        
        # Parse /proc/stat for the 'cpu' line
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('cpu '):
                    parts = line.strip().split()
                    # parts[1:] are user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
                    cpu_times = [float(x) for x in parts[1:]]
                    break
            else:
                cpu_times = []
        data = {
            'cpu_times': cpu_times,
            'status': 1
        }
        return HttpResponse(json.dumps(data), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'status': 0, 'error_message': str(e)}), content_type='application/json')

@csrf_exempt
@require_GET
def getRecentSSHLogins(request):
    try:
        user_id = request.session.get('userID')
        if not user_id:
            return HttpResponse(json.dumps({'error': 'Not logged in'}), content_type='application/json', status=403)
        currentACL = ACLManager.loadedACL(user_id)
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'error': 'Admin only'}), content_type='application/json', status=403)

        import re, time
        from collections import OrderedDict

        # Run 'last -n 20' to get recent SSH logins
        try:
            output = ProcessUtilities.outputExecutioner('last -n 20')
        except Exception as e:
            return HttpResponse(json.dumps({'error': 'Failed to run last: %s' % str(e)}), content_type='application/json', status=500)

        lines = output.strip().split('\n')
        logins = []
        ip_cache = {}
        for line in lines:
            if not line.strip() or any(x in line for x in ['reboot', 'system boot', 'wtmp begins']):
                continue
            # Example: ubuntu   pts/0        206.84.168.7     Sun Jun  1 19:41   still logged in
            # or:     ubuntu   pts/0        206.84.169.36    Tue May 27 11:34 - 13:47  (02:13)
            parts = re.split(r'\s+', line, maxsplit=5)
            if len(parts) < 5:
                continue
            user, tty, ip, *rest = parts
            # Find date/time and session info
            date_session = rest[-1] if rest else ''
            # Try to extract date/session
            date_match = re.search(r'([A-Za-z]{3} [A-Za-z]{3} +\d+ [\d:]+)', line)
            date_str = date_match.group(1) if date_match else ''
            session_info = ''
            if '-' in line:
                # Session ended
                session_info = line.split('-')[-1].strip()
            elif 'still logged in' in line:
                session_info = 'still logged in'
            # GeoIP lookup (cache per request)
            country = flag = ''
            if re.match(r'\d+\.\d+\.\d+\.\d+', ip) and ip != '127.0.0.1':
                if ip in ip_cache:
                    country, flag = ip_cache[ip]
                else:
                    try:
                        geo = requests.get(f'http://ip-api.com/json/{ip}', timeout=2).json()
                        country = geo.get('countryCode', '')
                        flag = f"https://flagcdn.com/24x18/{country.lower()}.png" if country else ''
                        ip_cache[ip] = (country, flag)
                    except Exception:
                        country, flag = '', ''
            elif ip == '127.0.0.1':
                country, flag = 'Local', ''
            logins.append({
                'user': user,
                'ip': ip,
                'country': country,
                'flag': flag,
                'date': date_str,
                'session': session_info,
                'raw': line
            })
        return HttpResponse(json.dumps({'logins': logins}), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'error': str(e)}), content_type='application/json', status=500)

@csrf_exempt
@require_GET
def getRecentSSHLogs(request):
    try:
        user_id = request.session.get('userID')
        if not user_id:
            return HttpResponse(json.dumps({'error': 'Not logged in'}), content_type='application/json', status=403)
        currentACL = ACLManager.loadedACL(user_id)
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'error': 'Admin only'}), content_type='application/json', status=403)
        from plogical.processUtilities import ProcessUtilities
        distro = ProcessUtilities.decideDistro()
        if distro in [ProcessUtilities.ubuntu, ProcessUtilities.ubuntu20]:
            log_path = '/var/log/auth.log'
        else:
            log_path = '/var/log/secure'
        try:
            output = ProcessUtilities.outputExecutioner(f'tail -n 100 {log_path}')
        except Exception as e:
            return HttpResponse(json.dumps({'error': f'Failed to read log: {str(e)}'}), content_type='application/json', status=500)
        lines = output.split('\n')
        logs = []
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) > 4:
                timestamp = ' '.join(parts[:3])
                message = ' '.join(parts[4:])
            else:
                timestamp = ''
                message = line
            logs.append({'timestamp': timestamp, 'message': message, 'raw': line})
        return HttpResponse(json.dumps({'logs': logs}), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'error': str(e)}), content_type='application/json', status=500)

@csrf_exempt
@require_POST
def analyzeSSHSecurity(request):
    try:
        user_id = request.session.get('userID')
        if not user_id:
            return HttpResponse(json.dumps({'error': 'Not logged in'}), content_type='application/json', status=403)
        currentACL = ACLManager.loadedACL(user_id)
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'error': 'Admin only'}), content_type='application/json', status=403)
        
        # Check if user has CyberPanel addons
        if not ACLManager.CheckForPremFeature('all'):
            return HttpResponse(json.dumps({
                'status': 0,
                'addon_required': True,
                'feature_title': 'SSH Security Analysis',
                'feature_description': 'Advanced SSH security monitoring and threat detection that helps protect your server from brute force attacks, port scanning, and unauthorized access attempts.',
                'features': [
                    'Real-time detection of brute force attacks',
                    'Identification of dictionary attacks and invalid login attempts',
                    'Port scanning detection',
                    'Root login attempt monitoring',
                    'Automatic security recommendations',
                    'Integration with CSF and Firewalld',
                    'Detailed threat analysis and reporting'
                ],
                'addon_url': 'https://cyberpanel.net/cyberpanel-addons'
            }), content_type='application/json')
        
        from plogical.processUtilities import ProcessUtilities
        import re
        from collections import defaultdict
        from datetime import datetime, timedelta
        
        alerts = []
        
        # Detect which firewall is in use
        firewall_cmd = ''
        try:
            # Check for CSF
            csf_check = ProcessUtilities.outputExecutioner('which csf')
            if csf_check and '/csf' in csf_check:
                firewall_cmd = 'csf'
        except:
            pass
        
        if not firewall_cmd:
            try:
                # Check for firewalld
                firewalld_check = ProcessUtilities.outputExecutioner('systemctl is-active firewalld')
                if firewalld_check and 'active' in firewalld_check:
                    firewall_cmd = 'firewalld'
            except:
                firewall_cmd = 'firewalld'  # Default to firewalld
        
        # Determine log path
        distro = ProcessUtilities.decideDistro()
        if distro in [ProcessUtilities.ubuntu, ProcessUtilities.ubuntu20]:
            log_path = '/var/log/auth.log'
        else:
            log_path = '/var/log/secure'
        
        try:
            # Get last 500 lines for better analysis
            output = ProcessUtilities.outputExecutioner(f'tail -n 500 {log_path}')
        except Exception as e:
            return HttpResponse(json.dumps({'error': f'Failed to read log: {str(e)}'}), content_type='application/json', status=500)
        
        lines = output.split('\n')
        
        # Analysis patterns
        failed_logins = defaultdict(int)
        failed_passwords = defaultdict(int)
        invalid_users = defaultdict(int)
        port_scan_attempts = defaultdict(int)
        suspicious_commands = []
        root_login_attempts = []
        successful_after_failures = defaultdict(list)
        connection_closed = defaultdict(int)
        repeated_connections = defaultdict(int)
        
        # Track IPs with failures for brute force detection
        ip_failures = defaultdict(list)
        
        # Track time-based patterns
        recent_attempts = defaultdict(list)
        
        for line in lines:
            if not line.strip():
                continue
            
            # Failed password attempts
            if 'Failed password' in line:
                match = re.search(r'Failed password for (?:invalid user )?(\S+) from (\S+)', line)
                if match:
                    user, ip = match.groups()
                    failed_passwords[ip] += 1
                    ip_failures[ip].append(('password', user, line))
                    
                    # Check for root login attempts
                    if user == 'root':
                        root_login_attempts.append({
                            'ip': ip,
                            'line': line
                        })
            
            # Invalid user attempts
            elif 'Invalid user' in line or 'invalid user' in line:
                match = re.search(r'[Ii]nvalid user (\S+) from (\S+)', line)
                if match:
                    user, ip = match.groups()
                    invalid_users[ip] += 1
                    ip_failures[ip].append(('invalid', user, line))
            
            # Port scan detection
            elif 'Did not receive identification string' in line or 'Bad protocol version identification' in line:
                match = re.search(r'from (\S+)', line)
                if match:
                    ip = match.group(1)
                    port_scan_attempts[ip] += 1
            
            # Successful login after failures
            elif 'Accepted' in line and 'for' in line:
                match = re.search(r'Accepted \S+ for (\S+) from (\S+)', line)
                if match:
                    user, ip = match.groups()
                    if ip in ip_failures:
                        successful_after_failures[ip].append({
                            'user': user,
                            'failures': len(ip_failures[ip]),
                            'line': line
                        })
            
            # Suspicious commands or activities
            elif any(pattern in line for pattern in ['COMMAND=', 'sudo:', 'su[', 'authentication failure']):
                if any(cmd in line for cmd in ['/etc/passwd', '/etc/shadow', 'chmod 777', 'rm -rf /', 'wget', 'curl', 'base64']):
                    suspicious_commands.append(line)
            
            # Connection closed by authenticating user
            elif 'Connection closed by authenticating user' in line:
                match = re.search(r'Connection closed by authenticating user \S+ (\S+)', line)
                if match:
                    ip = match.group(1)
                    connection_closed[ip] += 1
            
            # Repeated connection attempts
            elif 'Connection from' in line or 'Connection closed by' in line:
                match = re.search(r'from (\S+)', line)
                if match:
                    ip = match.group(1)
                    repeated_connections[ip] += 1
        
        # Generate alerts based on analysis
        
        # High severity: Brute force attacks
        for ip, count in failed_passwords.items():
            if count >= 10:
                if firewall_cmd == 'csf':
                    recommendation = f'Block this IP immediately:\ncsf -d {ip} "Brute force attack - {count} failed attempts"'
                else:
                    recommendation = f'Block this IP immediately:\nfirewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address={ip} drop" && firewall-cmd --reload'
                
                alerts.append({
                    'title': 'Brute Force Attack Detected',
                    'description': f'IP address {ip} has made {count} failed password attempts. This indicates a potential brute force attack.',
                    'severity': 'high',
                    'details': {
                        'IP Address': ip,
                        'Failed Attempts': count,
                        'Attack Type': 'Brute Force'
                    },
                    'recommendation': recommendation
                })
        
        # High severity: Root login attempts
        if root_login_attempts:
            alerts.append({
                'title': 'Root Login Attempts Detected',
                'description': f'Direct root login attempts detected from {len(set(r["ip"] for r in root_login_attempts))} IP addresses. Root SSH access should be disabled.',
                'severity': 'high',
                'details': {
                    'Unique IPs': len(set(r["ip"] for r in root_login_attempts)),
                    'Total Attempts': len(root_login_attempts),
                    'Top IP': max(set(r["ip"] for r in root_login_attempts), key=lambda x: sum(1 for r in root_login_attempts if r["ip"] == x))
                },
                'recommendation': 'Disable root SSH login by setting "PermitRootLogin no" in /etc/ssh/sshd_config'
            })
        
        # Medium severity: Dictionary attacks
        for ip, count in invalid_users.items():
            if count >= 5:
                if firewall_cmd == 'csf':
                    recommendation = f'Consider blocking this IP:\ncsf -d {ip} "Dictionary attack - {count} invalid users"\n\nAlso configure CSF Login Failure Daemon (lfd) for automatic blocking.'
                else:
                    recommendation = f'Consider blocking this IP:\nfirewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address={ip} drop" && firewall-cmd --reload\n\nAlso consider implementing fail2ban for automatic blocking.'
                
                alerts.append({
                    'title': 'Dictionary Attack Detected',
                    'description': f'IP address {ip} attempted to login with {count} non-existent usernames. This indicates a dictionary attack.',
                    'severity': 'medium',
                    'details': {
                        'IP Address': ip,
                        'Invalid User Attempts': count,
                        'Attack Type': 'Dictionary Attack'
                    },
                    'recommendation': recommendation
                })
        
        # Medium severity: Port scanning
        for ip, count in port_scan_attempts.items():
            if count >= 3:
                alerts.append({
                    'title': 'Port Scan Detected',
                    'description': f'IP address {ip} appears to be scanning SSH port with {count} connection attempts without proper identification.',
                    'severity': 'medium',
                    'details': {
                        'IP Address': ip,
                        'Scan Attempts': count,
                        'Attack Type': 'Port Scan'
                    },
                    'recommendation': 'Monitor this IP for further suspicious activity. Consider using port knocking or changing SSH port.'
                })
        
        # Low severity: Successful login after failures
        for ip, successes in successful_after_failures.items():
            if successes:
                max_failures = max(s['failures'] for s in successes)
                if max_failures >= 3:
                    alerts.append({
                        'title': 'Successful Login After Multiple Failures',
                        'description': f'IP address {ip} successfully logged in after {max_failures} failed attempts. This could be legitimate or a successful breach.',
                        'severity': 'low',
                        'details': {
                            'IP Address': ip,
                            'Failed Attempts Before Success': max_failures,
                            'Successful User': successes[0]['user']
                        },
                        'recommendation': 'Verify if this login is legitimate. Check user activity and consider enforcing stronger passwords.'
                    })
        
        # High severity: Rapid connection attempts (DDoS/flooding)
        for ip, count in repeated_connections.items():
            if count >= 50:
                if firewall_cmd == 'csf':
                    recommendation = f'Block this IP immediately to prevent resource exhaustion:\ncsf -d {ip} "SSH flooding - {count} connections"'
                else:
                    recommendation = f'Block this IP immediately to prevent resource exhaustion:\nfirewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address={ip} drop" && firewall-cmd --reload'
                
                alerts.append({
                    'title': 'SSH Connection Flooding Detected',
                    'description': f'IP address {ip} has made {count} rapid connection attempts. This may be a DDoS attack or connection flooding.',
                    'severity': 'high',
                    'details': {
                        'IP Address': ip,
                        'Connection Attempts': count,
                        'Attack Type': 'Connection Flooding'
                    },
                    'recommendation': recommendation
                })
        
        # Medium severity: Suspicious command execution
        if suspicious_commands:
            alerts.append({
                'title': 'Suspicious Command Execution Detected',
                'description': f'Detected {len(suspicious_commands)} suspicious command executions that may indicate system compromise.',
                'severity': 'medium',
                'details': {
                    'Suspicious Commands': len(suspicious_commands),
                    'Command Types': 'System file access, downloads, or dangerous operations',
                    'Sample': suspicious_commands[0] if suspicious_commands else ''
                },
                'recommendation': 'Review these commands immediately. If unauthorized, investigate the affected user accounts and consider:\n• Changing all passwords\n• Reviewing sudo access\n• Checking for backdoors or rootkits'
            })
        
        # Add general recommendations if no specific alerts
        if not alerts:
            # Check for best practices
            ssh_config_recommendations = []
            try:
                sshd_config = ProcessUtilities.outputExecutioner('grep -E "^(PermitRootLogin|PasswordAuthentication|Port)" /etc/ssh/sshd_config')
                if 'PermitRootLogin yes' in sshd_config:
                    ssh_config_recommendations.append('• Disable root login: Set "PermitRootLogin no" in /etc/ssh/sshd_config')
                if 'Port 22' in sshd_config:
                    ssh_config_recommendations.append('• Change default SSH port from 22 to reduce automated attacks')
            except:
                pass
            
            if ssh_config_recommendations:
                alerts.append({
                    'title': 'SSH Security Best Practices',
                    'description': 'While no immediate threats were detected, consider implementing these security enhancements.',
                    'severity': 'info',
                    'details': {
                        'Status': 'No Active Threats',
                        'Logs Analyzed': len(lines),
                        'Firewall': firewall_cmd.upper() if firewall_cmd else 'Unknown'
                    },
                    'recommendation': '\n'.join(ssh_config_recommendations)
                })
            else:
                alerts.append({
                    'title': 'No Immediate Threats Detected',
                    'description': 'No significant security threats were detected in recent SSH logs. Your SSH configuration follows security best practices.',
                    'severity': 'info',
                    'details': {
                        'Status': 'Secure',
                        'Logs Analyzed': len(lines),
                        'Firewall': firewall_cmd.upper() if firewall_cmd else 'Unknown'
                    },
                    'recommendation': 'Keep your system updated and continue regular security monitoring.'
                })
        
        # Sort alerts by severity
        severity_order = {'high': 0, 'medium': 1, 'low': 2, 'info': 3}
        alerts.sort(key=lambda x: severity_order.get(x['severity'], 3))
        
        return HttpResponse(json.dumps({
            'status': 1,
            'alerts': alerts
        }), content_type='application/json')
        
    except Exception as e:
        return HttpResponse(json.dumps({'error': str(e)}), content_type='application/json', status=500)

@csrf_exempt
@require_POST
def getSSHUserActivity(request):
    import json, os
    from plogical.processUtilities import ProcessUtilities
    try:
        user_id = request.session.get('userID')
        if not user_id:
            return HttpResponse(json.dumps({'error': 'Not logged in'}), content_type='application/json', status=403)
        currentACL = ACLManager.loadedACL(user_id)
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'error': 'Admin only'}), content_type='application/json', status=403)
        data = json.loads(request.body.decode('utf-8'))
        user = data.get('user')
        tty = data.get('tty')
        login_ip = data.get('ip', '')
        if not user:
            return HttpResponse(json.dumps({'error': 'Missing user'}), content_type='application/json', status=400)
        # Get processes for the user
        ps_cmd = f"ps -u {user} -o pid,ppid,tty,time,cmd --no-headers"
        try:
            ps_output = ProcessUtilities.outputExecutioner(ps_cmd)
        except Exception as e:
            ps_output = ''
        processes = []
        pid_map = {}
        if ps_output:
            for line in ps_output.strip().split('\n'):
                parts = line.split(None, 4)
                if len(parts) == 5:
                    pid, ppid, tty_val, time_val, cmd = parts
                    if tty and tty not in tty_val:
                        continue
                    # Try to get CWD
                    cwd = ''
                    try:
                        cwd_path = f"/proc/{pid}/cwd"
                        if os.path.islink(cwd_path):
                            cwd = os.readlink(cwd_path)
                    except Exception:
                        cwd = ''
                    proc = {
                        'pid': pid,
                        'ppid': ppid,
                        'tty': tty_val,
                        'time': time_val,
                        'cmd': cmd,
                        'cwd': cwd
                    }
                    processes.append(proc)
                    pid_map[pid] = proc
        # Build process tree
        tree = []
        def build_tree(parent_pid, level=0):
            for proc in processes:
                if proc['ppid'] == parent_pid:
                    proc_copy = proc.copy()
                    proc_copy['level'] = level
                    tree.append(proc_copy)
                    build_tree(proc['pid'], level+1)
        build_tree('1', 0)  # Start from init
        # Find main shell process for history
        shell_history = []
        try:
            try:
                website = Websites.objects.get(externalApp=user)
                shell_home = f'/home/{website.domain}'
            except Exception:
                shell_home = pwd.getpwnam(user).pw_dir
        except Exception:
            shell_home = f"/home/{user}"
        history_file = ''
        for shell in ['.bash_history', '.zsh_history']:
            path = os.path.join(shell_home, shell)
            if os.path.exists(path):
                history_file = path
                break
        if history_file:
            try:
                with open(history_file, 'r') as f:
                    lines = f.readlines()
                    shell_history = [l.strip() for l in lines[-10:]]
            except Exception:
                shell_history = []
        # Disk usage
        disk_usage = ''
        if os.path.exists(shell_home):
            try:
                du_out = ProcessUtilities.outputExecutioner(f'du -sh {shell_home}')
                disk_usage = du_out.strip().split('\t')[0] if du_out else ''
            except Exception:
                disk_usage = ''
        else:
            disk_usage = 'Home directory does not exist'
        # GeoIP details
        geoip = {}
        if login_ip and login_ip not in ['127.0.0.1', 'localhost']:
            try:
                geo = requests.get(f'http://ip-api.com/json/{login_ip}?fields=status,message,country,regionName,city,isp,org,as,query', timeout=2).json()
                if geo.get('status') == 'success':
                    geoip = {
                        'country': geo.get('country'),
                        'region': geo.get('regionName'),
                        'city': geo.get('city'),
                        'isp': geo.get('isp'),
                        'org': geo.get('org'),
                        'as': geo.get('as'),
                        'ip': geo.get('query')
                    }
            except Exception:
                geoip = {}
        # Optionally, get 'w' output for more info
        w_cmd = f"w -h {user}"
        try:
            w_output = ProcessUtilities.outputExecutioner(w_cmd)
        except Exception as e:
            w_output = ''
        w_lines = []
        if w_output:
            for line in w_output.strip().split('\n'):
                w_lines.append(line)
        return HttpResponse(json.dumps({
            'processes': processes,
            'process_tree': tree,
            'shell_history': shell_history,
            'disk_usage': disk_usage,
            'geoip': geoip,
            'w': w_lines
        }), content_type='application/json')
    except Exception as e:
        return HttpResponse(json.dumps({'error': str(e)}), content_type='application/json', status=500)

@csrf_exempt
@require_GET
def getTopProcesses(request):
    try:
        user_id = request.session.get('userID')
        if not user_id:
            return HttpResponse(json.dumps({'error': 'Not logged in'}), content_type='application/json', status=403)
        
        currentACL = ACLManager.loadedACL(user_id)
        if not currentACL.get('admin', 0):
            return HttpResponse(json.dumps({'error': 'Admin only'}), content_type='application/json', status=403)
        
        import subprocess
        import tempfile
        
        # Create a temporary file to capture top output
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Get top processes data
            with open(temp_path, "w") as outfile:
                subprocess.call("top -n1 -b", shell=True, stdout=outfile)
            
            with open(temp_path, 'r') as infile:
                data = infile.readlines()
            
            processes = []
            counter = 0
            
            for line in data:
                counter += 1
                if counter <= 7:  # Skip header lines
                    continue
                
                if len(processes) >= 10:  # Limit to top 10 processes
                    break
                
                points = line.split()
                points = [a for a in points if a != '']
                
                if len(points) >= 12:
                    process = {
                        'pid': points[0],
                        'user': points[1],
                        'cpu': points[8],
                        'memory': points[9],
                        'command': points[11]
                    }
                    processes.append(process)
            
            return HttpResponse(json.dumps({
                'status': 1,
                'processes': processes
            }), content_type='application/json')
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except Exception as e:
        return HttpResponse(json.dumps({'error': str(e)}), content_type='application/json', status=500)
