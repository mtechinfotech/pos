import shutil
import subprocess
import os
from mysqlUtilities import mysqlUtilities
import installLog as logging
import errno
import MySQLdb as mariadb
import install
from os.path import exists
import time
import install_utils

# distros - using from install_utils
centos = install_utils.centos
ubuntu = install_utils.ubuntu
cent8 = install_utils.cent8
openeuler = install_utils.openeuler


def get_Ubuntu_release():
    return install_utils.get_Ubuntu_release(use_print=True, exit_on_error=True)


def get_Ubuntu_code_name():
    """Get Ubuntu codename based on version"""
    release = get_Ubuntu_release()
    if release >= 24.04:
        return "noble"
    elif release >= 22.04:
        return "jammy"
    elif release >= 20.04:
        return "focal"
    elif release >= 18.04:
        return "bionic"
    else:
        return "xenial"


# Using shared function from install_utils
FetchCloudLinuxAlmaVersionVersion = install_utils.FetchCloudLinuxAlmaVersionVersion

class InstallCyberPanel:
    mysql_Root_password = ""
    mysqlPassword = ""
    CloudLinux8 = 0

    def install_package(self, package_name, options=""):
        """Unified package installation across distributions"""
        command, shell = install_utils.get_package_install_command(self.distro, package_name, options)
        
        # InstallCyberPanel always uses verbose mode (no silent option)
        if self.distro == ubuntu:
            return install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, shell)
        else:
            # For non-Ubuntu, original code didn't pass shell parameter
            return install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

    def manage_service(self, service_name, action="start"):
        """Unified service management"""
        service_map = {
            'mariadb': 'mariadb',
            'pureftpd': 'pure-ftpd-mysql' if self.distro == ubuntu else 'pure-ftpd',
            'pdns': 'pdns'
        }
        
        actual_service = service_map.get(service_name, service_name)
        command = f'systemctl {action} {actual_service}'
        return install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

    def modify_file_content(self, file_path, replacements):
        """Generic file content modification"""
        try:
            with open(file_path, 'r') as f:
                data = f.readlines()
            
            with open(file_path, 'w') as f:
                for line in data:
                    modified_line = line
                    for old, new in replacements.items():
                        if old in line:
                            modified_line = line.replace(old, new)
                            break
                    f.write(modified_line)
            return True
        except IOError as e:
            logging.InstallLog.writeToFile(f'[ERROR] {str(e)} [modify_file_content]')
            return False

    def copy_config_file(self, source_dir, dest_path, mysql_mode='One'):
        """Handle configuration file copying with mode selection"""
        # For directories like 'dns' vs 'dns-one', 'pure-ftpd' vs 'pure-ftpd-one'
        # Default mode is 'One' which uses the -one directories
        if mysql_mode == 'Two':
            source_path = source_dir
        else:
            # Default mode 'One' uses directories with -one suffix
            source_path = f"{source_dir}-one"
        
        # Ensure we're working with absolute paths
        if not os.path.isabs(source_path):
            source_path = os.path.join(self.cwd, source_path)
        
        # Determine the actual file to copy
        if os.path.isdir(source_path):
            # If dest_path is a file (like pdns.conf), copy the specific file
            if dest_path.endswith('.conf'):
                # Look for the specific config file
                source_file = os.path.join(source_path, os.path.basename(dest_path))
                if os.path.exists(source_file):
                    if os.path.exists(dest_path):
                        os.remove(dest_path)
                    shutil.copy(source_file, dest_path)
                else:
                    raise IOError(f"Source file {source_file} not found")
            else:
                # If it's a directory, copy the whole directory
                if os.path.exists(dest_path):
                    if os.path.isdir(dest_path):
                        shutil.rmtree(dest_path)
                shutil.copytree(source_path, dest_path)
        else:
            raise IOError(f"Source path {source_path} not found")

    @staticmethod
    def ISARM():

        try:
            command = 'uname -a'
            try:
                result = subprocess.run(command, capture_output=True, universal_newlines=True, shell=True)
            except:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)

            if 'aarch64' in result.stdout:
                return True
            else:
                return False
        except:
            return False

    @staticmethod
    def OSFlags():
        if os.path.exists("/etc/redhat-release"):
            data = open('/etc/redhat-release', 'r').read()

            if data.find('CloudLinux 8') > -1 or data.find('cloudlinux 8') > -1:
                InstallCyberPanel.CloudLinux8 = 1

    def __init__(self, rootPath, cwd, distro, ent, serial=None, port=None, ftp=None, dns=None, publicip=None,
                 remotemysql=None, mysqlhost=None, mysqldb=None, mysqluser=None, mysqlpassword=None, mysqlport=None):
        self.server_root_path = rootPath
        self.cwd = cwd
        self.distro = distro
        self.ent = ent
        self.serial = serial
        self.port = port
        self.ftp = None
        self.dns = dns
        self.publicip = publicip
        self.remotemysql = remotemysql
        self.mysqlhost = mysqlhost
        self.mysqluser = mysqluser
        self.mysqlpassword = mysqlpassword
        self.mysqlport = mysqlport
        self.mysqldb = mysqldb

        ## TURN ON OS FLAGS FOR SPECIFIC NEEDS LATER

        InstallCyberPanel.OSFlags()

    @staticmethod
    def stdOut(message, log=0, exit=0, code=os.EX_OK):
        install_utils.stdOut(message, log, exit, code)

    def installLiteSpeed(self):
        if self.ent == 0:
            self.install_package('openlitespeed')

        else:
            try:
                try:
                    command = 'groupadd nobody'
                    install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)
                except:
                    pass

                try:
                    command = 'usermod -a -G nobody nobody'
                    install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)
                except:
                    pass

                if InstallCyberPanel.ISARM():
                    command = 'wget https://www.litespeedtech.com/packages/6.0/lsws-6.2-ent-aarch64-linux.tar.gz'
                else:
                    command = 'wget https://www.litespeedtech.com/packages/6.0/lsws-6.2-ent-x86_64-linux.tar.gz'

                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                if InstallCyberPanel.ISARM():
                    command = 'tar zxf lsws-6.2-ent-aarch64-linux.tar.gz'
                else:
                    command = 'tar zxf lsws-6.2-ent-x86_64-linux.tar.gz'

                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                if str.lower(self.serial) == 'trial':
                    command = 'wget -q --output-document=lsws-6.2/trial.key http://license.litespeedtech.com/reseller/trial.key'
                if self.serial == '1111-2222-3333-4444':
                    command = 'wget -q --output-document=/root/cyberpanel/install/lsws-6.2/trial.key http://license.litespeedtech.com/reseller/trial.key'
                    install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)
                else:
                    writeSerial = open('lsws-6.2/serial.no', 'w')
                    writeSerial.writelines(self.serial)
                    writeSerial.close()

                shutil.copy('litespeed/install.sh', 'lsws-6.2/')
                shutil.copy('litespeed/functions.sh', 'lsws-6.2/')

                os.chdir('lsws-6.2')

                command = 'chmod +x install.sh'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = 'chmod +x functions.sh'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = './install.sh'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                os.chdir(self.cwd)
                confPath = '/usr/local/lsws/conf/'
                shutil.copy('litespeed/httpd_config.xml', confPath)
                shutil.copy('litespeed/modsec.conf', confPath)
                shutil.copy('litespeed/httpd.conf', confPath)

                command = 'chown -R lsadm:lsadm ' + confPath
                install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)

            except BaseException as msg:
                logging.InstallLog.writeToFile('[ERROR] ' + str(msg) + " [installLiteSpeed]")
                return 0

            return 1

    def reStartLiteSpeed(self):
        command = install_utils.format_restart_litespeed_command(self.server_root_path)
        install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)

    def fix_ols_configs(self):
        try:

            InstallCyberPanel.stdOut("Fixing OpenLiteSpeed configurations!", 1)

            ## remove example virtual host

            data = open(self.server_root_path + "conf/httpd_config.conf", 'r').readlines()

            writeDataToFile = open(self.server_root_path + "conf/httpd_config.conf", 'w')

            for items in data:
                if items.find("map") > -1 and items.find("Example") > -1:
                    continue
                else:
                    writeDataToFile.writelines(items)

            writeDataToFile.close()

            InstallCyberPanel.stdOut("OpenLiteSpeed Configurations fixed!", 1)
        except IOError as msg:
            logging.InstallLog.writeToFile('[ERROR] ' + str(msg) + " [fix_ols_configs]")
            return 0

        return self.reStartLiteSpeed()

    def changePortTo80(self):
        try:
            InstallCyberPanel.stdOut("Changing default port to 80..", 1)

            file_path = self.server_root_path + "conf/httpd_config.conf"
            if self.modify_file_content(file_path, {"*:8088": "*:80"}):
                InstallCyberPanel.stdOut("Default port is now 80 for OpenLiteSpeed!", 1)
            else:
                return 0

        except Exception as msg:
            logging.InstallLog.writeToFile('[ERROR] ' + str(msg) + " [changePortTo80]")
            return 0

        return self.reStartLiteSpeed()

    def installAllPHPVersions(self):
        php_versions = ['71', '72', '73', '74', '80', '81', '82', '83']
        
        if self.distro == ubuntu:
            # Install base PHP 7.x packages
            command = 'DEBIAN_FRONTEND=noninteractive apt-get -y install ' \
                      'lsphp7? lsphp7?-common lsphp7?-curl lsphp7?-dev lsphp7?-imap lsphp7?-intl lsphp7?-json ' \
                      'lsphp7?-ldap lsphp7?-mysql lsphp7?-opcache lsphp7?-pspell lsphp7?-recode ' \
                      'lsphp7?-sqlite3 lsphp7?-tidy'
            os.system(command)
            
            # Install PHP 8.x versions
            for version in php_versions[4:]:  # 80, 81, 82, 83
                self.install_package(f'lsphp{version}*')
                
        elif self.distro == centos:
            # First install the group
            command = 'yum -y groupinstall lsphp-all'
            install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)
            
            InstallCyberPanel.stdOut("LiteSpeed PHPs successfully installed!", 1)
            
            # Install individual PHP versions
            for version in php_versions:
                self.install_package(f'lsphp{version}*', '--skip-broken')
                
        elif self.distro == cent8:
            # Install PHP versions in batches with exclusions
            exclude_flags = "--exclude lsphp73-pecl-zip --exclude *imagick*"
            
            # First batch: PHP 7.x and 8.0
            versions_batch1 = ' '.join([f'lsphp{v}*' for v in php_versions[:5]])
            self.install_package(versions_batch1, f'{exclude_flags} --skip-broken')
            
            # Second batch: PHP 8.1+
            versions_batch2 = ' '.join([f'lsphp{v}*' for v in php_versions[5:]])
            self.install_package(versions_batch2, f'{exclude_flags} --skip-broken')
            
        elif self.distro == openeuler:
            # Install all PHP versions at once
            all_versions = ' '.join([f'lsphp{v}*' for v in php_versions])
            self.install_package(all_versions)
            
        if self.distro != ubuntu:
            InstallCyberPanel.stdOut("LiteSpeed PHPs successfully installed!", 1)

    def installMySQL(self, mysql):

        ############## Install mariadb ######################

        if self.distro == ubuntu:

            command = 'DEBIAN_FRONTEND=noninteractive apt-get install software-properties-common apt-transport-https curl -y'
            install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

            command = "mkdir -p /etc/apt/keyrings"
            install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

            command = "curl -o /etc/apt/keyrings/mariadb-keyring.pgp 'https://mariadb.org/mariadb_release_signing_key.pgp'"
            install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)
            RepoPath = '/etc/apt/sources.list.d/mariadb.sources'
            RepoContent = f"""
# MariaDB 10.11 repository list - created 2023-12-11 07:53 UTC
# https://mariadb.org/download/
X-Repolib-Name: MariaDB
Types: deb
# deb.mariadb.org is a dynamic mirror if your preferred mirror goes offline. See https://mariadb.org/mirrorbits/ for details.
# URIs: https://deb.mariadb.org/10.11/ubuntu
URIs: https://mirrors.gigenet.com/mariadb/repo/10.11/ubuntu
Suites: jammy
Components: main main/debug
Signed-By: /etc/apt/keyrings/mariadb-keyring.pgp
"""

            if get_Ubuntu_release() > 21.00:
                command = 'curl -LsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash -s -- --mariadb-server-version=10.11'
                result = install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR, True)
                
                # If the download fails, use manual repo configuration as fallback
                if result != 1:
                    install_utils.writeToFile("MariaDB repo setup script failed, using manual configuration...")
                    
                    # First, ensure directories exist
                    command = 'mkdir -p /usr/share/keyrings /etc/apt/sources.list.d'
                    install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)
                    
                    # Download and add MariaDB signing key
                    command = 'curl -fsSL https://mariadb.org/mariadb_release_signing_key.pgp | gpg --dearmor -o /usr/share/keyrings/mariadb-keyring.pgp'
                    install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)
                    
                    # Use multiple mirror options for better reliability
                    RepoPath = '/etc/apt/sources.list.d/mariadb.list'
                    codename = get_Ubuntu_code_name()
                    RepoContent = f"""# MariaDB 10.11 repository list - manual fallback
# Primary mirror
deb [arch=amd64,arm64,ppc64el,s390x signed-by=/usr/share/keyrings/mariadb-keyring.pgp] https://mirror.mariadb.org/repo/10.11/ubuntu {codename} main

# Alternative mirrors (uncomment if primary fails)
# deb [arch=amd64,arm64,ppc64el,s390x signed-by=/usr/share/keyrings/mariadb-keyring.pgp] https://mirrors.gigenet.com/mariadb/repo/10.11/ubuntu {codename} main
# deb [arch=amd64,arm64,ppc64el,s390x signed-by=/usr/share/keyrings/mariadb-keyring.pgp] https://ftp.osuosl.org/pub/mariadb/repo/10.11/ubuntu {codename} main
"""
                    
                    WriteToFile = open(RepoPath, 'w')
                    WriteToFile.write(RepoContent)
                    WriteToFile.close()
                    
                    install_utils.writeToFile("Manual MariaDB repository configuration completed.")



            command = 'DEBIAN_FRONTEND=noninteractive apt-get update -y'
            install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)


            command = "DEBIAN_FRONTEND=noninteractive apt-get install mariadb-server -y"
        elif self.distro == centos:

            RepoPath = '/etc/yum.repos.d/mariadb.repo'
            RepoContent = f"""
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.11/rhel8-amd64
module_hotfixes=1
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1            
"""
            WriteToFile = open(RepoPath, 'w')
            WriteToFile.write(RepoContent)
            WriteToFile.close()

            command = 'dnf install mariadb-server -y'
        elif self.distro == cent8 or self.distro == openeuler:

            clAPVersion = FetchCloudLinuxAlmaVersionVersion()
            type = clAPVersion.split('-')[0]
            version = int(clAPVersion.split('-')[1])


            if type == 'cl' and version >= 88:

                command = 'yum remove db-governor db-governor-mysql -y'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

                command = 'yum install governor-mysql -y'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

                command = '/usr/share/lve/dbgovernor/mysqlgovernor.py --mysql-version=mariadb106'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

                command = '/usr/share/lve/dbgovernor/mysqlgovernor.py --install --yes'

            else:

                command = 'curl -LsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash -s -- --mariadb-server-version=10.11'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

                command = 'yum remove mariadb* -y'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

                command = 'sudo dnf -qy module disable mariadb'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

                command = 'sudo dnf module reset mariadb -y'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)


                command = 'dnf install MariaDB-server MariaDB-client MariaDB-backup -y'

        install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)

        ############## Start mariadb ######################

        self.startMariaDB()

    def changeMYSQLRootPassword(self):
        if self.remotemysql == 'OFF':
            if self.distro == ubuntu:
                passwordCMD = "use mysql;DROP DATABASE IF EXISTS test;DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%%';GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY '%s';UPDATE user SET plugin='' WHERE User='root';flush privileges;" % (
                    InstallCyberPanel.mysql_Root_password)
            else:
                passwordCMD = "use mysql;DROP DATABASE IF EXISTS test;DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%%';GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY '%s';flush privileges;" % (
                    InstallCyberPanel.mysql_Root_password)

            command = 'mariadb -u root -e "' + passwordCMD + '"'

            install_utils.call(command, self.distro, command, command, 0, 0, os.EX_OSERR)

    def startMariaDB(self):

        if self.remotemysql == 'OFF':
            ############## Start mariadb ######################
            self.manage_service('mariadb', 'start')

            ############## Enable mariadb at system startup ######################

            if os.path.exists('/etc/systemd/system/mysqld.service'):
                os.remove('/etc/systemd/system/mysqld.service')
            if os.path.exists('/etc/systemd/system/mariadb.service'):
                os.remove('/etc/systemd/system/mariadb.service')

            self.manage_service('mariadb', 'enable')

    def fixMariaDB(self):
        self.stdOut("Setup MariaDB so it can support Cyberpanel's needs")

        conn = mariadb.connect(user='root', passwd=self.mysql_Root_password)
        cursor = conn.cursor()
        cursor.execute('set global innodb_file_per_table = on;')
        try:
            cursor.execute('set global innodb_file_format = Barracuda;')
            cursor.execute('set global innodb_large_prefix = on;')
        except BaseException as msg:
            self.stdOut('%s. [ERROR:335]' % (str(msg)))
        cursor.close()
        conn.close()

        try:
            fileName = '/etc/mysql/mariadb.conf.d/50-server.cnf'
            data = open(fileName, 'r').readlines()

            writeDataToFile = open(fileName, 'w')
            for line in data:
                writeDataToFile.write(line.replace('utf8mb4', 'utf8'))
            writeDataToFile.close()
        except IOError as err:
            self.stdOut("[ERROR] Error in setting: " + fileName + ": " + str(err), 1, 1, os.EX_OSERR)

        os.system('systemctl restart mariadb')

        self.stdOut("MariaDB is now setup so it can support Cyberpanel's needs")

    def installPureFTPD(self):
        if self.distro == ubuntu:
            self.install_package('pure-ftpd-mysql')

            if get_Ubuntu_release() == 18.10:
                # Special handling for Ubuntu 18.10
                packages = [
                    ('pure-ftpd-common_1.0.47-3_all.deb', 'wget https://rep.cyberpanel.net/pure-ftpd-common_1.0.47-3_all.deb'),
                    ('pure-ftpd-mysql_1.0.47-3_amd64.deb', 'wget https://rep.cyberpanel.net/pure-ftpd-mysql_1.0.47-3_amd64.deb')
                ]
                
                for filename, wget_cmd in packages:
                    install_utils.call(wget_cmd, self.distro, wget_cmd, wget_cmd, 1, 1, os.EX_OSERR)
                    command = f'dpkg --install --force-confold {filename}'
                    install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)
        else:
            self.install_package('pure-ftpd')

        ####### Install pureftpd to system startup

        command = "systemctl enable " + install.preFlightsChecks.pureFTPDServiceName(self.distro)
        install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

        ###### FTP Groups and user settings settings

        command = 'groupadd -g 2001 ftpgroup'
        install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

        command = 'useradd -u 2001 -s /bin/false -d /bin/null -c "pureftpd user" -g ftpgroup ftpuser'
        install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

    def startPureFTPD(self):
        ############## Start pureftpd ######################
        serviceName = install.preFlightsChecks.pureFTPDServiceName(self.distro)
        
        # During fresh installation, don't start Pure-FTPd yet
        # It will be started after Django migrations create the required tables
        InstallCyberPanel.stdOut("Pure-FTPd enabled for startup.", 1)
        InstallCyberPanel.stdOut("Note: Pure-FTPd will start after database setup is complete.", 1)
        logging.InstallLog.writeToFile("Pure-FTPd enabled but not started - waiting for Django migrations")

    def installPureFTPDConfigurations(self, mysql):
        try:
            ## setup ssl for ftp

            InstallCyberPanel.stdOut("Configuring PureFTPD..", 1)

            try:
                if not os.path.exists("/etc/ssl/private"):
                    os.makedirs("/etc/ssl/private", mode=0o755)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    logging.InstallLog.writeToFile("[ERROR] Could not create directory for FTP SSL: " + str(e))
                    raise

            if (self.distro == centos or self.distro == cent8 or self.distro == openeuler) or (
                    self.distro == ubuntu and get_Ubuntu_release() == 18.14):
                command = 'openssl req -newkey rsa:1024 -new -nodes -x509 -days 3650 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem'
            else:
                command = 'openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -subj "/C=US/ST=Denial/L=Sprinal-ield/O=Dis/CN=www.example.com" -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem'

            install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)

            os.chdir(self.cwd)
            ftpdPath = "/etc/pure-ftpd"

            self.copy_config_file("pure-ftpd", ftpdPath, mysql)

            if self.distro == ubuntu:
                try:
                    os.mkdir('/etc/pure-ftpd/conf')
                    os.mkdir('/etc/pure-ftpd/auth')
                    os.mkdir('/etc/pure-ftpd/db')
                except OSError as err:
                    self.stdOut("[ERROR] Error creating extra pure-ftpd directories: " + str(err), ".  Should be ok", 1)

            data = open(ftpdPath + "/pureftpd-mysql.conf", "r").readlines()

            writeDataToFile = open(ftpdPath + "/pureftpd-mysql.conf", "w")

            dataWritten = "MYSQLPassword " + InstallCyberPanel.mysqlPassword + '\n'
            for items in data:
                if items.find("MYSQLPassword") > -1:
                    writeDataToFile.writelines(dataWritten)
                else:
                    writeDataToFile.writelines(items)

            writeDataToFile.close()

            ftpConfPath = '/etc/pure-ftpd/pureftpd-mysql.conf'

            if self.remotemysql == 'ON':
                command = "sed -i 's|localhost|%s|g' %s" % (self.mysqlhost, ftpConfPath)
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = "sed -i 's|3306|%s|g' %s" % (self.mysqlport, ftpConfPath)
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = "sed -i 's|MYSQLSocket /var/lib/mysql/mysql.sock||g' %s" % (ftpConfPath)
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

            if self.distro == ubuntu:

                if os.path.exists('/etc/pure-ftpd/db/mysql.conf'):
                    os.remove('/etc/pure-ftpd/db/mysql.conf')
                    shutil.copy(ftpdPath + "/pureftpd-mysql.conf", '/etc/pure-ftpd/db/mysql.conf')
                else:
                    shutil.copy(ftpdPath + "/pureftpd-mysql.conf", '/etc/pure-ftpd/db/mysql.conf')

                command = 'echo 1 > /etc/pure-ftpd/conf/TLS'
                subprocess.call(command, shell=True)

                command = 'echo %s > /etc/pure-ftpd/conf/ForcePassiveIP' % (self.publicip)
                subprocess.call(command, shell=True)

                command = 'echo "40110 40210" > /etc/pure-ftpd/conf/PassivePortRange'
                subprocess.call(command, shell=True)

                command = 'echo "no" > /etc/pure-ftpd/conf/UnixAuthentication'
                subprocess.call(command, shell=True)

                command = 'echo "/etc/pure-ftpd/db/mysql.conf" > /etc/pure-ftpd/conf/MySQLConfigFile'
                subprocess.call(command, shell=True)

                command = 'ln -s /etc/pure-ftpd/conf/MySQLConfigFile /etc/pure-ftpd/auth/30mysql'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = 'ln -s /etc/pure-ftpd/conf/UnixAuthentication /etc/pure-ftpd/auth/65unix'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = 'systemctl restart pure-ftpd-mysql.service'
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)




                if get_Ubuntu_release() > 21.00:
                    ### change mysql md5 to crypt

                    command = "sed -i 's/MYSQLCrypt md5/MYSQLCrypt crypt/g' /etc/pure-ftpd/db/mysql.conf"
                    install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                    command = "systemctl restart pure-ftpd-mysql.service"
                    install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)
            else:

                try:
                    clAPVersion = FetchCloudLinuxAlmaVersionVersion()
                    type = clAPVersion.split('-')[0]
                    version = int(clAPVersion.split('-')[1])

                    if type == 'al' and version >= 90:
                        command = "sed -i 's/MYSQLCrypt md5/MYSQLCrypt crypt/g' /etc/pure-ftpd/pureftpd-mysql.conf"
                        install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)
                except:
                    pass



            InstallCyberPanel.stdOut("PureFTPD configured!", 1)

        except IOError as msg:
            logging.InstallLog.writeToFile('[ERROR] ' + str(msg) + " [installPureFTPDConfigurations]")
            return 0

    def installPowerDNS(self):
        try:
            if self.distro == ubuntu or self.distro == cent8 or self.distro == openeuler:
                # Stop and disable systemd-resolved
                self.manage_service('systemd-resolved', 'stop')
                self.manage_service('systemd-resolved.service', 'disable')

                try:
                    os.rename('/etc/resolv.conf', '/etc/resolv.conf.bak')
                except OSError as e:
                    if e.errno != errno.EEXIST and e.errno != errno.ENOENT:
                        InstallCyberPanel.stdOut("[ERROR] Unable to rename /etc/resolv.conf to install PowerDNS: " +
                                                 str(e), 1, 1, os.EX_OSERR)
                
                # Create a temporary resolv.conf with Google DNS for package installation
                try:
                    with open('/etc/resolv.conf', 'w') as f:
                        f.write('nameserver 8.8.8.8\n')
                        f.write('nameserver 8.8.4.4\n')
                    InstallCyberPanel.stdOut("Created temporary /etc/resolv.conf with Google DNS", 1)
                except IOError as e:
                    InstallCyberPanel.stdOut("[ERROR] Unable to create /etc/resolv.conf: " + str(e), 1, 1, os.EX_OSERR)

            # Install PowerDNS packages
            if self.distro == ubuntu:
                # Update package list first
                command = "DEBIAN_FRONTEND=noninteractive apt-get update"
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)
                
                # Install PowerDNS packages
                command = "DEBIAN_FRONTEND=noninteractive apt-get -y install pdns-server pdns-backend-mysql"
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR, True)
                
                # Ensure service is stopped after installation for configuration
                command = 'systemctl stop pdns || true'
                install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR, True)
                return 1
            else:
                self.install_package('pdns pdns-backend-mysql')

        except BaseException as msg:
            logging.InstallLog.writeToFile('[ERROR] ' + str(msg) + " [powerDNS]")

    def installPowerDNSConfigurations(self, mysqlPassword, mysql):
        try:

            InstallCyberPanel.stdOut("Configuring PowerDNS..", 1)

            os.chdir(self.cwd)
            if self.distro == centos or self.distro == cent8 or self.distro == openeuler:
                dnsPath = "/etc/pdns/pdns.conf"
            else:
                dnsPath = "/etc/powerdns/pdns.conf"
                # Ensure directory exists for Ubuntu
                dnsDir = os.path.dirname(dnsPath)
                if not os.path.exists(dnsDir):
                    try:
                        os.makedirs(dnsDir, mode=0o755)
                    except OSError as e:
                        if e.errno != errno.EEXIST:
                            raise

            try:
                self.copy_config_file("dns", dnsPath, mysql)
            except Exception as e:
                InstallCyberPanel.stdOut("[ERROR] Failed to copy PowerDNS config: " + str(e), 1)
                logging.InstallLog.writeToFile('[ERROR] Failed to copy PowerDNS config: ' + str(e))
                raise

            # Verify the file was copied and has content
            if not os.path.exists(dnsPath):
                raise IOError(f"PowerDNS config file not found at {dnsPath} after copy")
            
            # Check if file has content
            with open(dnsPath, "r") as f:
                content = f.read()
                if not content or "launch=gmysql" not in content:
                    InstallCyberPanel.stdOut("[WARNING] PowerDNS config appears empty or incomplete, attempting to fix...", 1)
                    
                    # First try to re-copy
                    try:
                        if os.path.exists(dnsPath):
                            os.remove(dnsPath)
                        source_file = os.path.join(self.cwd, "dns-one", "pdns.conf")
                        shutil.copy2(source_file, dnsPath)
                    except Exception as copy_error:
                        InstallCyberPanel.stdOut("[WARNING] Failed to re-copy config: " + str(copy_error), 1)
                        
                        # Fallback: directly write the essential MySQL configuration
                        InstallCyberPanel.stdOut("[INFO] Directly writing MySQL backend configuration...", 1)
                        try:
                            mysql_config = f"""# PowerDNS MySQL Backend Configuration
launch=gmysql
gmysql-host=localhost
gmysql-port=3306
gmysql-user=cyberpanel
gmysql-password={mysqlPassword}
gmysql-dbname=cyberpanel

# Basic PowerDNS settings
daemon=no
guardian=no
setgid=pdns
setuid=pdns
"""
                            # If file exists and has some content, append our config
                            if os.path.exists(dnsPath) and content.strip():
                                # Check if it's just missing the MySQL part
                                with open(dnsPath, "a") as f:
                                    f.write("\n\n" + mysql_config)
                            else:
                                # Write a complete minimal config
                                with open(dnsPath, "w") as f:
                                    f.write(mysql_config)
                            
                            InstallCyberPanel.stdOut("[SUCCESS] MySQL backend configuration written directly", 1)
                        except Exception as write_error:
                            InstallCyberPanel.stdOut("[ERROR] Failed to write MySQL config: " + str(write_error), 1)
                            raise
            
            InstallCyberPanel.stdOut("PowerDNS config file prepared at: " + dnsPath, 1)
            
            data = open(dnsPath, "r").readlines()

            writeDataToFile = open(dnsPath, "w")

            dataWritten = "gmysql-password=" + mysqlPassword + "\n"

            for items in data:
                if items.find("gmysql-password") > -1:
                    writeDataToFile.writelines(dataWritten)
                else:
                    writeDataToFile.writelines(items)

            # if self.distro == ubuntu:
            #    os.fchmod(writeDataToFile.fileno(), stat.S_IRUSR | stat.S_IWUSR)

            writeDataToFile.close()

            if self.remotemysql == 'ON':
                command = "sed -i 's|gmysql-host=localhost|gmysql-host=%s|g' %s" % (self.mysqlhost, dnsPath)
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

                command = "sed -i 's|gmysql-port=3306|gmysql-port=%s|g' %s" % (self.mysqlport, dnsPath)
                install_utils.call(command, self.distro, command, command, 1, 1, os.EX_OSERR)

            # Set proper permissions for PowerDNS config
            if self.distro == ubuntu:
                # Ensure pdns user/group exists
                command = 'id -u pdns &>/dev/null || useradd -r -s /usr/sbin/nologin pdns'
                install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)
                
                command = 'chown root:pdns %s' % dnsPath
                install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)
                
                command = 'chmod 640 %s' % dnsPath
                install_utils.call(command, self.distro, command, command, 1, 0, os.EX_OSERR)

            InstallCyberPanel.stdOut("PowerDNS configured!", 1)

        except IOError as msg:
            logging.InstallLog.writeToFile('[ERROR] ' + str(msg) + " [installPowerDNSConfigurations]")
            return 0
        return 1

    def startPowerDNS(self):

        ############## Start PowerDNS ######################

        self.manage_service('pdns', 'enable')
        
        # During fresh installation, don't start PowerDNS yet
        # It will be started after Django migrations create the required tables
        InstallCyberPanel.stdOut("PowerDNS enabled for startup.", 1)
        InstallCyberPanel.stdOut("Note: PowerDNS will start after database setup is complete.", 1)
        logging.InstallLog.writeToFile("PowerDNS enabled but not started - waiting for Django migrations")
        
        # The service will be started later after migrations run
        # or manually by the admin after installation completes


def Main(cwd, mysql, distro, ent, serial=None, port="8090", ftp=None, dns=None, publicip=None, remotemysql=None,
         mysqlhost=None, mysqldb=None, mysqluser=None, mysqlpassword=None, mysqlport=None):
    InstallCyberPanel.mysqlPassword = install_utils.generate_pass()
    InstallCyberPanel.mysql_Root_password = install_utils.generate_pass()

    file_name = '/etc/cyberpanel/mysqlPassword'

    if remotemysql == 'OFF':
        if os.access(file_name, os.F_OK):
            password = open(file_name, 'r')
            InstallCyberPanel.mysql_Root_password = password.readline()
            password.close()
        else:
            password = open(file_name, "w")
            password.writelines(InstallCyberPanel.mysql_Root_password)
            password.close()
    else:
        mysqlData = {'remotemysql': remotemysql, 'mysqlhost': mysqlhost, 'mysqldb': mysqldb, 'mysqluser': mysqluser,
                     'mysqlpassword': mysqlpassword, 'mysqlport': mysqlport}
        from json import dumps
        writeToFile = open(file_name, 'w')
        writeToFile.write(dumps(mysqlData))
        writeToFile.close()

        if install.preFlightsChecks.debug:
            print(open(file_name, 'r').read())
            time.sleep(10)

    try:
        command = 'chmod 640 %s' % (file_name)
        install_utils.call(command, distro, '[chmod]',
                                      '',
                                      1, 0, os.EX_OSERR)
        command = 'chown root:cyberpanel %s' % (file_name)
        install_utils.call(command, distro, '[chmod]',
                                      '',
                                      1, 0, os.EX_OSERR)
    except:
        pass

    if distro == centos:
        InstallCyberPanel.mysqlPassword = install_utils.generate_pass()
    else:
        InstallCyberPanel.mysqlPassword = InstallCyberPanel.mysql_Root_password

    installer = InstallCyberPanel("/usr/local/lsws/", cwd, distro, ent, serial, port, ftp, dns, publicip, remotemysql,
                                  mysqlhost, mysqldb, mysqluser, mysqlpassword, mysqlport)

    logging.InstallLog.writeToFile('Installing LiteSpeed Web server,40')
    installer.installLiteSpeed()
    if ent == 0:
        installer.changePortTo80()
    logging.InstallLog.writeToFile('Installing Optimized PHPs..,50')
    installer.installAllPHPVersions()
    if ent == 0:
        installer.fix_ols_configs()

    logging.InstallLog.writeToFile('Installing MySQL,60')
    installer.installMySQL(mysql)
    installer.changeMYSQLRootPassword()

    installer.startMariaDB()

    if remotemysql == 'OFF':
        if distro == ubuntu:
            installer.fixMariaDB()

    mysqlUtilities.createDatabase("cyberpanel", "cyberpanel", InstallCyberPanel.mysqlPassword, publicip)

    if ftp is None:
        installer.installPureFTPD()
        installer.installPureFTPDConfigurations(mysql)
        installer.startPureFTPD()
    else:
        if ftp == 'ON':
            installer.installPureFTPD()
            installer.installPureFTPDConfigurations(mysql)
            installer.startPureFTPD()

    if dns is None:
        installer.installPowerDNS()
        installer.installPowerDNSConfigurations(InstallCyberPanel.mysqlPassword, mysql)
        installer.startPowerDNS()
    else:
        if dns == 'ON':
            installer.installPowerDNS()
            installer.installPowerDNSConfigurations(InstallCyberPanel.mysqlPassword, mysql)
            installer.startPowerDNS()
