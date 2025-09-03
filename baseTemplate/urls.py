from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^$', views.renderBase, name='index'),
    re_path(r'^getSystemStatus$', views.getSystemStatus, name='getSystemInformation'),
    re_path(r'^getAdminStatus$', views.getAdminStatus, name='getSystemInformation'),
    re_path(r'^getLoadAverage$', views.getLoadAverage, name='getLoadAverage'),
    re_path(r'^versionManagment$', views.versionManagment, name='versionManagment'),
    re_path(r'^design$', views.design, name='design'),
    re_path(r'^getthemedata$', views.getthemedata, name='getthemedata'),
    re_path(r'^upgrade$', views.upgrade, name='upgrade'),
    re_path(r'^onboarding$', views.onboarding, name='onboarding'),
    re_path(r'^RestartCyberPanel$', views.RestartCyberPanel, name='RestartCyberPanel'),
    re_path(r'^runonboarding$', views.runonboarding, name='runonboarding'),
    re_path(r'^UpgradeStatus$', views.upgradeStatus, name='UpgradeStatus'),
    re_path(r'^upgradeVersion$', views.upgradeVersion, name='upgradeVersion'),
    re_path(r'^getDashboardStats$', views.getDashboardStats, name='getDashboardStats'),
    re_path(r'^getTrafficStats$', views.getTrafficStats, name='getTrafficStats'),
    re_path(r'^getDiskIOStats$', views.getDiskIOStats, name='getDiskIOStats'),
    re_path(r'^getCPULoadGraph$', views.getCPULoadGraph, name='getCPULoadGraph'),
    re_path(r'^getRecentSSHLogins$', views.getRecentSSHLogins, name='getRecentSSHLogins'),
    re_path(r'^getRecentSSHLogs$', views.getRecentSSHLogs, name='getRecentSSHLogs'),
    re_path(r'^getSSHUserActivity$', views.getSSHUserActivity, name='getSSHUserActivity'),
    re_path(r'^getTopProcesses$', views.getTopProcesses, name='getTopProcesses'),
    re_path(r'^analyzeSSHSecurity$', views.analyzeSSHSecurity, name='analyzeSSHSecurity'),
]
