# -*- coding: utf-8 -*-
from django.shortcuts import render,redirect
from loginSystem.models import Administrator
from loginSystem.views import loadLoginPage
import plogical.CyberCPLogFileWriter as logging
from django.http import HttpResponse
import json
from websiteFunctions.models import Websites
from plogical.acl import ACLManager
from .filemanager import FileManager as FM
# Create your views here.

def loadFileManagerHome(request,domain):
    try:
        # Check if user is logged in
        if 'userID' not in request.session:
            # Not logged in, redirect to login page
            from loginSystem.views import loadLoginPage
            return loadLoginPage(request)
            
        userID = request.session['userID']
        
        if Websites.objects.filter(domain=domain).exists():
            admin = Administrator.objects.get(pk=userID)
            currentACL = ACLManager.loadedACL(userID)

            if ACLManager.checkOwnership(domain, admin, currentACL) == 1:
                # Get IP address for base template context
                ipAddress = ACLManager.fetchIP()
                
                # Prepare context for base template
                from plogical.acl import ACLManager as ACL
                context = {
                    'domainName': domain,
                    'ipAddress': ipAddress,
                    'admin': currentACL.get('admin', 0),
                    'createNewUser': currentACL.get('createNewUser', 0),
                    'listUsers': currentACL.get('listUsers', 0),
                    'resellerCenter': currentACL.get('resellerCenter', 0),
                    'createWebsite': currentACL.get('createWebsite', 0),
                    'modifyWebsite': currentACL.get('modifyWebsite', 0),
                    'suspendWebsite': currentACL.get('suspendWebsite', 0),
                    'deleteWebsite': currentACL.get('deleteWebsite', 0),
                    'createPackage': currentACL.get('createPackage', 0),
                    'listPackages': currentACL.get('listPackages', 0),
                    'deletePackage': currentACL.get('deletePackage', 0),
                    'modifyPackage': currentACL.get('modifyPackage', 0),
                    'createDatabase': currentACL.get('createDatabase', 0),
                    'deleteDatabase': currentACL.get('deleteDatabase', 0),
                    'listDatabases': currentACL.get('listDatabases', 0),
                    'createNameServer': currentACL.get('createNameServer', 0),
                    'createDNSZone': currentACL.get('createDNSZone', 0),
                    'deleteZone': currentACL.get('deleteZone', 0),
                    'addDeleteRecords': currentACL.get('addDeleteRecords', 0),
                    'createEmail': currentACL.get('createEmail', 0),
                    'listEmails': currentACL.get('listEmails', 0),
                    'deleteEmail': currentACL.get('deleteEmail', 0),
                    'emailForwarding': currentACL.get('emailForwarding', 0),
                    'changeEmailPassword': currentACL.get('changeEmailPassword', 0),
                    'dkimManager': currentACL.get('dkimManager', 0),
                    'createFTPAccount': currentACL.get('createFTPAccount', 0),
                    'deleteFTPAccount': currentACL.get('deleteFTPAccount', 0),
                    'listFTPAccounts': currentACL.get('listFTPAccounts', 0),
                    'createBackup': currentACL.get('createBackup', 0),
                    'restoreBackup': currentACL.get('restoreBackup', 0),
                    'addDeleteDestinations': currentACL.get('addDeleteDestinations', 0),
                    'scheduleBackups': currentACL.get('scheduleBackups', 0),
                    'googleDriveBackups': currentACL.get('googleDriveBackups', 0),
                    'remoteBackups': currentACL.get('remoteBackups', 0),
                    'manageSSL': currentACL.get('manageSSL', 0),
                    'hostnameSSL': currentACL.get('hostnameSSL', 0),
                    'mailServerSSL': currentACL.get('mailServerSSL', 0)
                }
                
                # Check for server type for context
                from plogical.processUtilities import ProcessUtilities
                if ProcessUtilities.decideServer() == ProcessUtilities.OLS:
                    context['serverCheck'] = 0
                else:
                    context['serverCheck'] = 1
                
                # Check if we should use integrated template
                # For now, use standard template by default, but allow override
                template = 'filemanager/index.html'
                if request.GET.get('integrated', '0') == '1':
                    template = 'filemanager/indexIntegrated.html'
                elif request.GET.get('modern', '0') == '1':
                    template = 'filemanager/indexModern.html'
                
                return render(request, template, context)
            else:
                return ACLManager.loadError()
        else:
            return HttpResponse("Domain does not exists.")

    except Exception as e:
        logging.CyberCPLogFileWriter.writeToFile(f"File Manager Error: {str(e)}")
        from loginSystem.views import loadLoginPage
        return loadLoginPage(request)

def changePermissions(request):
    try:
        userID = request.session['userID']

        try:
            data = json.loads(request.body)
            domainName = data['domainName']

            currentACL = ACLManager.loadedACL(userID)

            if currentACL['admin'] == 1:
                pass
            else:
                return ACLManager.loadError()

            fm = FM(request, data)
            fm.fixPermissions(domainName)

            data_ret = {'permissionsChanged': 1, 'error_message': "None"}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

        except BaseException as msg:
            logging.CyberCPLogFileWriter.writeToFile(str(msg))
            data_ret = {'permissionsChanged': 0, 'error_message': str(msg)}
            json_data = json.dumps(data_ret)
            return HttpResponse(json_data)

    except KeyError:
        return redirect(loadLoginPage)

def controller(request):
    try:
        data = json.loads(request.body)

        try:
            domainName = data['domainName']
            method = data['method']

            userID = request.session['userID']
            admin = Administrator.objects.get(pk=userID)
            currentACL = ACLManager.loadedACL(userID)

            if domainName == '':
                if currentACL['admin'] == 1:
                    pass
                else:
                    return ACLManager.loadErrorJson('FilemanagerAdmin', 0)
            else:
                if ACLManager.checkOwnership(domainName, admin, currentACL) == 1:
                    pass
                else:
                    return ACLManager.loadErrorJson()
        except:
            method = data['method']
            userID = request.session['userID']
            currentACL = ACLManager.loadedACL(userID)

            if currentACL['admin'] == 1:
                pass
            else:
                return ACLManager.loadErrorJson('FilemanagerAdmin', 0)

        fm = FM(request, data)

        if method == 'listForTable':
            return fm.listForTable()
        elif method == 'list':
            return fm.list()
        elif method == 'createNewFile':
            return fm.createNewFile()
        elif method == 'createNewFolder':
            return fm.createNewFolder()
        elif method == 'deleteFolderOrFile':
            return fm.deleteFolderOrFile()
        elif method == 'restore':
            return fm.restore()
        elif method == 'copy':
            return fm.copy()
        elif method == 'move':
            return fm.move()
        elif method == 'rename':
            return fm.rename()
        elif method == 'readFileContents':
            return fm.readFileContents()
        elif method == 'writeFileContents':
            return fm.writeFileContents()
        elif method == 'upload':
            return fm.writeFileContents()
        elif method == 'extract':
            return fm.extract()
        elif method == 'compress':
            return fm.compress()
        elif method == 'changePermissions':
            return fm.changePermissions()


    except BaseException as msg:
        fm = FM(request, None)
        return fm.ajaxPre(0, str(msg))

def upload(request):
    try:

        data = request.POST

        try:

            userID = request.session['userID']
            admin = Administrator.objects.get(pk=userID)
            currentACL = ACLManager.loadedACL(userID)

            if ACLManager.checkOwnership(data['domainName'], admin, currentACL) == 1:
                pass
            else:
                return ACLManager.loadErrorJson()
        except:
            return ACLManager.loadErrorJson()

        fm = FM(request, data)
        return fm.upload()

    except KeyError:
        return redirect(loadLoginPage)

def editFile(request):
    try:
        userID = request.session['userID']
        admin = Administrator.objects.get(pk=userID)
        from urllib.parse import quote
        from django.utils.encoding import iri_to_uri

        domainName = request.GET.get('domainName')
        fileName = request.GET.get('fileName')

        try:
            theme = request.GET.get('theme')
            if theme == None:
                theme = 'cobalt'
        except:
            theme = 'cobalt'

        currentACL = ACLManager.loadedACL(userID)

        if ACLManager.checkOwnership(domainName, admin, currentACL) == 1:
            pass
        else:
            return ACLManager.loadError()

        mode = FM.findMode(fileName)
        modeFiles = FM.findModeFiles(mode)
        additionalOptions = FM.findAdditionalOptions(mode)
        themeFile = FM.findThemeFile(theme)

        if ACLManager.checkOwnership(domainName, admin, currentACL) == 1:
            return render(request, 'filemanager/editFile.html', {'domainName': domainName, 'fileName': fileName,
                                                                 'mode': mode, 'modeFiles': modeFiles, 'theme': theme,
                                                                 'themeFile': themeFile, 'additionalOptions': additionalOptions})
        else:
            return ACLManager.loadError()

    except KeyError:
        return redirect(loadLoginPage)

def FileManagerRoot(request):
    ### Load Custom CSS
    try:
        from baseTemplate.models import CyberPanelCosmetic
        cosmetic = CyberPanelCosmetic.objects.get(pk=1)
    except:
        from baseTemplate.models import CyberPanelCosmetic
        cosmetic = CyberPanelCosmetic()
        cosmetic.save()

    ipAddressLocal = ACLManager.fetchIP()

    try:

        from plogical.processUtilities import ProcessUtilities
        if ProcessUtilities.decideServer() == ProcessUtilities.OLS:

            url = "https://platform.cyberpersons.com/CyberpanelAdOns/Adonpermission"
            data = {
                "name": "Filemanager",
                 "IP": ipAddressLocal
            }

            import requests
            response = requests.post(url, data=json.dumps(data))
            Status = response.json()['status']

            if(Status == 1):
                template = 'baseTemplate/FileManager.html'
            else:
              return  redirect("https://cyberpanel.net/cyberpanel-addons")
        else:
            template = 'baseTemplate/FileManager.html'
    except BaseException as msg:
        template = 'baseTemplate/FileManager.html'

    from plogical.httpProc import httpProc
    proc = httpProc(request, template, None, 'admin')
    return proc.render()

def downloadFile(request):
    try:
        userID = request.session['userID']
        admin = Administrator.objects.get(pk=userID)
        from urllib.parse import quote
        from django.utils.encoding import iri_to_uri

        fileToDownload = request.build_absolute_uri().split('fileToDownload')[1][1:]
        fileToDownload = iri_to_uri(fileToDownload)

        domainName = request.GET.get('domainName')

        currentACL = ACLManager.loadedACL(userID)

        if ACLManager.checkOwnership(domainName, admin, currentACL) == 1:
            pass
        else:
            return ACLManager.loadErrorJson('permissionsChanged', 0)

        homePath = '/home/%s' % (domainName)

        if fileToDownload.find('..') > -1 or fileToDownload.find(homePath) == -1:
            return HttpResponse("Unauthorized access.")

        response = HttpResponse(content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename=%s' % (fileToDownload.split('/')[-1])
        response['X-LiteSpeed-Location'] = '%s' % (fileToDownload)

        return response

    except KeyError:
        return redirect(loadLoginPage)

def RootDownloadFile(request):
    try:
        userID = request.session['userID']
        from urllib.parse import quote
        from django.utils.encoding import iri_to_uri

        fileToDownload = request.build_absolute_uri().split('fileToDownload')[1][1:]
        fileToDownload = iri_to_uri(fileToDownload)

        currentACL = ACLManager.loadedACL(userID)

        if currentACL['admin'] == 1:
            pass
        else:
            return ACLManager.loadError()

        response = HttpResponse(content_type='application/force-download')
        response['Content-Disposition'] = 'attachment; filename=%s' % (fileToDownload.split('/')[-1])
        response['X-LiteSpeed-Location'] = '%s' % (fileToDownload)

        return response
        #return HttpResponse(response['X-LiteSpeed-Location'])
    except KeyError:
        return redirect(loadLoginPage)
