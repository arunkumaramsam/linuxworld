
#!/bin/bash

#############Linux Hardening Script####################################################
#                                                                                     #
##############Author:Ratheesh Vasudevan#####################################################

###configuring services###
chkconfig autofs on
chkconfig acpid off
chkconfig anacron off
chkconfig apmd off
chkconfig arptables_jf off
chkconfig arpwatch off
chkconfig atd off
chkconfig avahi-daemon on
chkconfig auditd on
chkconfig autofs on
chkconfig avahi-dnsconfd off
chkconfig bluetooth off
chkconfig conman off
chkconfig cups off
chkconfig cpuspeed on
chkconfig crond on
chkconfig cyrus-imapd off
chkconfig dc_client off
chkconfig dc_server off
chkconfig firstboot off
chkconfig dovecot off
chkconfig dund off
chkconfig haldaemon off
chkconfig hidd off
chkconfig hplip off
chkconfig isdn off
chkconfig iptables off
chkconfig ip6tables off
chkconfig irda off
chkconfig irqbalance on
chkconfig iscsi on
chkconfig iscsid on
chkconfig kdump off
chkconfig kudzu off
chkconfig krb524 off
chkconfig kprop off
chkconfig mcstrans off
chkconfig mailman off
chkconfig mcstrains off
chkconfig microcode_ctl off
chkconfig multipathd off
chkconfig netconsole off
chkconfig netfs on
chkconfig netplugd off
chkconfig nfs on
chkconfig nfslock on
chkconfig ntpd on
chkconfig nscd off
chkconfig pcscd off
chkconfig portmap on
chkconfig rdisc off
chkconfig rhnsd off
chkconfig restorecond on
chkconfig rpcgssd off
chkconfig rpcidmapd off
chkconfig ripd off
chkconfig ripngd off
chkconfig rpcsvcgssd off
chkconfig sendmail off
chkconfig smartd off
chkconfig snmpd on
chkconfig setroubleshoot off
chkconfig sshd on
chkconfig syslog on
chkconfig sysstat on
chkconfig winbind off
chkconfig wpa_supplicant off
chkconfig xfs off
chkconfig ypbind off
chkconfig yum-updatesd off
chkconfig acpid on
chkconfig anacron on
chkconfig atd on
chkconfig cpuspeed on
chkconfig lvm2-monitor on
chkconfig messagebus on
chkconfig ntpd on
chkconfig network on
chkconfig readahead_early off
chkconfig readahead_later off
chkconfig syslog on
chkconfig sshd on
chkconfig vncserver on
chkconfig xend off
chkconfig xfs off
chkconfig zebra off
chkconfig chargen-dgram off
chkconfig chargen-stream off
chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig echo-dgram off
chkconfig echo-stream off
chkconfig tcpmux-server off

echo "3.1-Configured necessory services in startup" >> /tmp/linuxreport.txt

########Backing up important files#######################

mkdir /linux_bkp

cp -a /etc/pam.d/system-auth /linux_bkp/system_auth_bkp
cp -a /etc/grub.conf /linux_bkp/grub.conf_bkp
cp -a /etc/inittab /linux_bkp/inittab_bkp
cp -a /etc/sysctl.conf /linux_bkp/sysctl.conf_bkp
cp -a /etc/sysconfig/init /linux_bkp/init_bkp
cp -a /etc/sysconfig/prelink /linux_bkp/prelink_bkp
cp -a /etc/security/limits.conf /linux_bkp/limits.conf_bkp
cp -a /etc/syslog.conf /linux_bkp/syslog.conf_bkp
cp -a /etc/audit/audit.conf /linux_bkp/auditd.conf_bkp
cp -a /etc/audit/audit.rules /linux_bkp/audit.rules_bkp
cp -a /etc/ssh/sshd_config /linux_bkp/sshd_config_bkp
cp -a /etc/login.defs /linux_bkp/login.defs_bkp

echo "Important Files are backedup" >> /tmp/linuxreport.txt

#Adding NODEV in /dev/shm partition

nodev_chk1=`cat /etc/fstab |grep /dev/shm |grep nodev | wc -l`
nodev_chk2=`mount |grep /dev/shm |grep nodev |wc -l`
if [ $nodev_chk1 -gt 0 ] || [ $nodev_chk2 -gt 0 ]; then

mount -o remount,nodev,noexec,nosuid /dev/shm

echo "3.2.1-NODEV is added in /dev/shm " >> /tmp/linuxreport.txt

else

echo "3.2.1-/dev/shm is already mounted with nodev" >> /tmp/linuxreport.txt

fi

#Adding nosuid in /dev/shm partition

nosuid_chk1=`cat /etc/fstab |grep /dev/shm |grep nosuid | wc -l`
nosuid_chk2=`mount |grep /dev/shm |grep nosuid | wc -l`

if [ $nosuid_chk1 -gt 0 ] || [ $nosuid_chk2 -gt 0 ]; then

mount -o remount,nodev,noexec,nosuid /dev/shm

echo "3.2.2-nosuid is added in /dev/shm" >> /tmp/linuxreport.txt

else

echo "3.2.2-/dev/shm is already mounted with nosuid" >> /tmp/linuxreport.txt

fi

#Adding noexec in /dev/shm partition

noexec_chk1=`cat /etc/fstab |grep /dev/shm |grep noexec | wc -l`
noexec_chk2=`mount |grep /dev/shm |grep noexec | wc -l`

if [ $noexec_chk1 -gt 0 ] || [ $noexec_chk2 -gt 0 ]; then

mount -o remount,nodev,noexec,nosuid /dev/shm

echo "3.2.3-noexec is added in /dev/shm" >> /tmp/linuxreport.txt
else

echo "3.2.3-/dev/shm is already mounted with noexec" >> /tmp/linuxreport.txt

fi

#Install AIDE

rpm -qa |grep aide


if [ $? -eq 1 ]; then

cd /tmp/linuxhardening

rpm -ivh aide*.rpm --nodeps

echo "3.4.1-AIDE is installed succesfully" >> /tmp/linuxreport.txt

else

echo "3.4.1-AIDE is already installed" >> /tmp/linuxreport.txt

fi

#3.4.2-Periodic Execution of File integrity 

crontab -l |grep aide

if [ $? -eq 1 ]; then

crontab -l > mycron

echo "0 1 * * * /usr/sbin/aide -check" >> mycron

crontab mycron

echo "3.4.2- Periodic execution of file inegrity is configured" >> /tmp/linuxreport.txt

fi

#3.6.1-Set user and group owner for grub.conf

chown root:root /etc/grub.conf

echo "3.6.1-user and owner configuration is done for /etc/grub.conf" >> /tmp/linuxreport.txt

#3.6.2-Set permission on /etc/groub.conf

chmod og-rwx /etc/grub.conf

echo "3.6.2-permission is setted for /etc/grub.conf" >> /tmp/linuxreport.txt

#3.6.4-Set authentication for single user mode

echo ~:S:wait:/sbin/sulogin >> /etc/inittab

if [ $? -eq 0 ]; then

echo "3.6.4-authentication is configured successfully for single user mode" >> /tmp/linuxreport.txt

else

echo "3.6.4-Failed to configure authentication in single user mode" >> /tmp/linuxreport.txt

fi
#3.6.5-Disable interactive boot

grep "PROMPT=no" /etc/sysconfig/init

if [ $? -eq 1 ]; then

echo "3.6.5-Disabling interactive boot" >> /tmp/linuxreport.txt

sed -i 's/PROMPT=yes/PROMPT=no/g' /etc/sysconfig/init

else

echo "3.6.5-Interactive boot is already enabled"

fi

#3.7.1 Restrict Core Dumps

echo * hard core 0 >> /etc/security/limits.conf
echo fs.suid.dumpable = 0 >> /etc/sysctl.conf
echo "3.7.1-core dump is restricted" >> /tmp/linuxreport.txt

#3.7.2 Configure ExecShield

echo kernel.exec-shield = 1 >> /etc/sysctl.conf

echo "3.7.2-Execshield is configured" >> /tmp/linuxreport.txt

#3.7.5 Disable Prelink

sed -i 's/PRELINKING=yes/PRELINKING=no/g'  /etc/sysconfig/prelink

echo "3.7.5-Prelinking is disabled" >> /tmp/linuxreport.txt

#3.8.1 Remove telnet server

tntsrv=`rpm -qa |grep telnet-server`

if [ $? -eq 0 ]; then

rpm -e $tntsev

echo "3.8.1-telnet-server is removed" >> /tmp/linuxreport.txt

else

echo "3.8.1-telnet-server is not installed" >> /tmp/linuxreport.txt

fi

#3.8.3 Remove RSH server

rsh=`rpm -qa |grep rsh-server`

if [ $? -eq 0 ]; then

rpm -e $rsh

echo "3.8.3-rsh-server is removed" >> /tmp/linuxreport.txt

else

echo "3.8.3-rsh-server is not installed" >> /tmp/linuxreport.txt

fi

#3.8.4  Remove NIS client

ypb=`rpm -qa |grep ypbind`

if [ $? -eq 0 ]; then

rpm -e $ypb --nodeps

echo "3.8.4-NIS client is removed" >> /tmp/linuxreport.txt

else

echo "3.8.4-NIS client is not installed" >> /tmp/linuxreport.txt

fi


#3.8.5 Remove NIS server

yps=`rpm -qa |grep ypserv`

if [ $? -eq 0 ]; then

rpm -e $yps

echo "3.8.5-NIS server is removed" >> /tmp/linuxreport.txt

else

echo "3.8.5-NIS server is not installed" >> /tmp/linuxreport.txt

fi

#3.8.6 Remove TFTP

tfp=`rpm -qa |grep tftp`

if [ $? -eq 0 ]; then

rpm -e $tfp

echo "3.8.6-tftp server is removed" >> /tmp/linuxreport.txt

else

echo "3.8.6-tftp server is not installed" >> /tmp/linuxreport.txt

fi

#3.8.8 Remove Talk

tlk=`rpm -qa |grep talk`

if [ $? -eq 0 ]; then

rpm -e $tlk

echo "3.8.8-talk is removed" >> /tmp/linuxreport.txt

else

echo "3.8.8-talk is not installed" >> /tmp/linuxreport.txt

fi

#3.8.9 Remove talk-server

tlks=`rpm -qa |grep talk-server`

if [ $? -eq 0 ]; then

rpm -e $tlks

echo "3.8.9-talk server is removed" >> /tmp/linuxreport.txt

else

echo "3.8.9-talk server is not installed" >> /tmp/linuxreport.txt

fi

######3.9#####Secure OS services###################

#3.9.2 Disable print server CUPS

chkconfig cups off

if [ $? -eq 0 ]; then

echo "3.9.2-cups is disabled for this system" >> /tmp/linuxreport.txt

else

echo "3.9.2-cups is not installed" >> /tmp/linuxreport.txt

fi
#3.9.8 Remove Davecot

rpm -qa |grep davecot

if [ $? -eq 0 ]; then

rpm -e davecot*.rpm --nodeps

echo "3.9.8-davecot is removed" >> /tmp/linuxreport.txt

else

echo "3.9.8-davecot is not installed" >> /tmp/linuxreport.txt

fi

#3.9.9 Remove Samba

$smb=`rpm -qa |grep samba |grep -v samba-client`

if [ $? -eq 0 ]; then

rpm -e $smb --nodeps

echo "3.9.9-samba server is removed" >> /tmp/linuxreport.txt

else

echo "3.9.9-samba server is not installed" >> /tmp/linuxreport.txt

fi

######3.10########## Secure Network configuration 

#3.10.2 Disable Send packet redirects

/sbin/sysctl net.ipv4.conf.all.send_redirects |grep 1

if [ $? -eq 0 ]; then

/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.send_redirects =0


echo "3.10.2-Disabling send packet redirects is configured" >> /tmp/linuxreport.txt

else

echo "3.10.2-Disabling send packet redirects is failed" >> /tmp/linuxreport.txt

fi
#3.10.6 Log Suspicious packets

/sbin/sysctl net.ipv4.conf.all.log_martians |grep 0

if [ $? -eq 0 ]; then

/sbin/sysctl -w net.ipv4.conf.all.log_martians=1
/sbin/sysctl -w net.ipv4.route.flush=1

echo "3.10.6-Logging un-routable packets are configured" >> /tmp/linuxreport.txt

else

echo "3.10.6-Logging un-routable packets configuration is failed" >> /tmp/linuxreport.txt

fi

#3.10.8 Enable bad error Message protection

/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses |grep 1

if [ $? -eq 1 ]; then

/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
/sbin/sysctl -w net.ipv4.route.flush=1

echo "3.10.8-Bad error Message Protection is configured" >> /tmp/linuxreport.txt

else

echo "3.10.8-Bad error Message Protection is configuration is failed" >> /tmp/linuxreport.txt
fi

#3.10.9 Enable TCP SYN Cookies


/sbin/sysctl net.ipv4.tcp_syncookies |grep 0

if [ $? -eq 1 ]; then

/sbin/sysctl -w net.ipv4.tcp_syncookies=1
/sbin/sysctl -w net.ipv4.route.flush=1

echo "3.10.9-TCP SYN Cookies are congigured successfully" >> /tmp/linuxreport.txt

else

echo "3.10.9-TCP SYN Cookies are congiguration is failed" >> /tmp/linuxreport.txt

fi

#3.10.10 Disable IPv6

grep ipv6 /etc/modprobe.conf

if [ $? -eq 1 ]; then


echo options ipv6 "disable=1" >> /etc/modprobe.conf

echo "3.10.10-IPv6 is disabled sucessfully" >> /tmp/linuxreport.txt

else 

echo "3.10.10-IPv6 is not installed" >> /tmp/linuxreport.txt

fi

####3.11 Secure Logging and Auditing functions##############################################

#3.11.1 Configure /etc/syslog.conf

echo auth,user.* /var/log/messages >> /etc/syslog.conf

echo kern.* /var/log/kern.log >> /etc/syslog.conf

echo daemon.* /var/log/daemon.log >> /etc/syslog.conf

echo syslog.* /var/log/syslog >> /etc/syslog.conf

echo news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log >> /etc/syslog.conf

pkill -HUP syslogd

if [ $? -eq 0 ]; then

echo "3.11.1-syslog.conf is configured successfully" >> /tmp/linuxreport.txt

else

echo "3.11.1-syslog.conf is configuration is failed" >> /tmp/linuxreport.txt

fi

#3.11.2 Create and Set Permissions on syslog Log Files
cd /var/log
for LOG in \
messages kern.log daemon.log syslog \

do 

chown -R root:root /var/log/$LOG 
chmod og-rwx /var/log/$LOG

echo " 3.11.2-Permissions are set for syslog files" >> /tmp/linuxreport.txt
done

#3.11.5 Install the rsyslog package

rpm -qa |grep rsyslog


if [ $? -eq 1 ]; then

cd /tmp/linuxhardening

rpm -ivh rsyslog*.rpm --nodeps

echo "3.11.5-rsyslog is configured" >> /tmp/linuxreport.txt


else

echo "3.11.5-rsyslog is already installed" >> /tmp/linuxreport.txt

fi

#3.11.6 Activate the rsyslog Service

chkconfig syslog off
chkconfig rsyslog on

echo " 3.11.6-rsyslog service is activated successfully" >> /tmp/linuxreport.txt 

#3.11.7 configure /etc/rsyslog.conf

echo auth,user.* /var/log/messages >> /etc/rsyslog.conf

echo kern.* /var/log/kern.log >> /etc/rsyslog.conf

echo daemon.* /var/log/daemon.log >> /etc/rsyslog.conf

echo syslog.* /var/log/syslog >> /etc/rsyslog.conf

echo news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log >> /etc/rsyslog.conf

pkill -HUP rsyslogd

if [ $? -eq 0 ]; then

echo "3.11.7-rsyslog is configured successfully" >> /tmp/linuxreport.txt

else

echo "3.11.7-rsyslog is configuration is failed" >> /tmp/linuxreport.txt

fi

#3.11.8 Create and Set Permissions on rsyslog Log Files

cd /var/log
for LOG in \
messages kern.log daemon.log syslog \

do 

chown -R root:root /var/log/$LOG 
chmod og-rwx /var/log/$LOG

echo " 3.11.8-Permissions are set for rsyslog files" >> /tmp/linuxreport.txt
done

#3.11.10 Enable auditd Service

chkconfig auditd on

if [ $? -eq 0 ]; then

echo "3.11.10 auditd service is enabled" >> /tmp/linuxreport.txt

else "3.11.10-enabling audit service is failed, please check audit service is installed or not" >> /tmp/linuxreport.txt

fi

#3.11.11 Configure Audit Log Storage Size

sed -i 's/max_log_file = 5/#max_log_file = 5/g' /etc/audit/auditd.conf
echo max_log_file = MB >> /etc/audit/auditd.conf

if [ $? -eq 0 ]; then

echo "3.11.11 Configure Audit Log Storage Size is successful" >> /tmp/linuxreport.txt

else

echo "3.11.11 Configure Audit Log Storage Size is failed" >> /tmp/linuxreport.txt

fi

#3.11.12 Keep All Auditing Information

echo max_log_file_action = keep_logs >> /etc/audit/auditd.conf

if [ $? -eq 0 ]; then

echo "3.11.12 Configure Audit Log is successful" >> /tmp/linuxreport.txt

else

echo "3.11.12 Configure Audit Log is failed" >> /tmp/linuxreport.txt

fi

#3.11.14 Record Events That Modify Date and Time Information

os_arch=`getconf LONG_BIT` 

if [ $os_arch -eq 32 ]; then 

echo -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S clock_settime -k time-change >> /etc/audit/audit.rules

echo -w /etc/localtime -p wa -k time-change >> /etc/audit/audit.rules 

pkill -HUP auditd 

echo "3.11.4-Configuration to record Events That Modify Date and Time Information updated successfully for 32bit OS" >> /tmp/linuxreport.txt

else 

echo -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change >> /etc/audit/audit.rules

echo -a always,exit -F arch=b64 -S clock_settime -k time-change >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S clock_settime -k time-change >> /etc/audit/audit.rules

echo -w /etc/localtime -p wa -k time-change >> /etc/audit/audit.rules

pkill -HUP auditd 

echo "3.11.4-Configuration to record Events That Modify Date and Time Information updated successfully for 64bit OS" >> /tmp/linuxreport.txt

fi 

#3.11.15 Record Events That Modify User/Group Information


echo -w /etc/group -p wa -k identity >> /etc/audit/audit.rules

echo -w /etc/passwd -p wa -k identity >> /etc/audit/audit.rules

echo -w /etc/gshadow -p wa -k identity >> /etc/audit/audit.rules

echo -w /etc/shadow -p wa -k identity >> /etc/audit/audit.rules

echo -w /etc/security/opasswd -p wa -k identity >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.15-Configuration to record events that modify User/Group information in audit logs" >> /tmp/linuxreport.txt

#3.11.16 Record Events That Modify the System’s Network Environment

os_arch=`getconf LONG_BIT` 

if [ $os_arch -eq 32 ]; then

echo -a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale >> /etc/audit/audit.rules

echo -w /etc/issue -p wa -k system-locale >> /etc/audit/audit.rules

echo -w /etc/issue.net -p wa -k system-locale >> /etc/audit/audit.rules

echo -w /etc/hosts -p wa -k system-locale >> /etc/audit/audit.rules

echo -w /etc/sysconfig/network -p wa -k system-locale >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.16-Configuration to Record Events That Modify the System’s Network Environment is successfully configured for 32 bit OS" >> /tmp/linuxreport.txt

else 

echo -a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale >> /etc/audit/audit.rules

echo -a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale >> /etc/audit/audit.rules

echo -w /etc/issue -p wa -k system-locale >> /etc/audit/audit.rules

echo -w /etc/issue.net -p wa -k system-locale >> /etc/audit/audit.rules

echo -w /etc/hosts -p wa -k system-locale >> /etc/audit/audit.rules

echo -w /etc/sysconfig/network -p wa -k system-locale >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.16-Configuration to Record Events That Modify the System’s Network Environment is successfully configured for 64 bit OS" >> /tmp/linuxreport.txt

fi

#3.11.17 Collect Login and Logout Events

echo -w /var/log/faillog -p wa -k logins >> /etc/audit/audit.rules

echo -w /var/log/lastlog -p wa -k logins >> /etc/audit/audit.rules

echo -w /var/log/tallylog -p -wa -k logins >> /etc/audit/audit.rules

echo -w /var/log/btmp -p wa -k session >> /etc/audit/audit.rules

pkill -HUP auditd 

echo "3.11.17-Configuration to Collect Login and Logout Events is successfully configured in audit rules" >> /tmp/linuxreport.txt

#3.11.18 Collect Session Initiation Information


echo -w /var/run/utmp -p wa -k session >> /etc/audit/audit.rules

echo -w /var/log/wtmp -p wa -k session >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.18-Configuration to Collect Session Initiation Information is successfully configured in audit rules" >> /tmp/linuxreport.txt

#3.11.19 Collect Discretionary Access Control Permission Modification Events

os_arch=`getconf LONG_BIT` 

if [ $os_arch -eq 32 ]; then

echo -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -Slchown -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \ >> /etc/audit/audit.rules

echo lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.19-Configuration to Collect Discretionary Access Control Permission Modification Events is successfully updated in audit rules for 32 bit OS" >> /tmp/linuxreport.txt

else

echo -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \ >> /etc/audit/audit.rules

echo lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S \ >> /etc/audit/audit.rules

echo lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.19-Configuration to Collect Discretionary Access Control Permission Modification Events is successfully updated in audit rules for 64 bit OS" >> /tmp/linuxreport.txt

fi

#3.11.20 Collect Unsuccessful Unauthorized Access Attempts to Files

os_arch=`getconf LONG_BIT` 

if [ $os_arch -eq 32 ]; then

echo -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate \ >> /etc/audit/audit.rules

echo -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate \ >> /etc/audit/audit.rules

echo -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.20-Configuration to Collect Unsuccessful Unauthorized Access Attempts to Files is successfully updated in audit rules for 32 bit OS" >> /tmp/linuxreport.txt

else 

echo -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate \ >> /etc/audit/audit.rules

echo -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate \ >> /etc/audit/audit.rules

echo -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access >> /etc/audit/audit.rules

echo -a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate \ >> /etc/audit/audit.rules

echo -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate \ >> /etc/audit/audit.rules

echo -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.20-Configuration to Collect Unsuccessful Unauthorized Access Attempts to Files is successfully updated in audit rules for 64 bit OS" >> /tmp/linuxreport.txt

fi 

#3.11.22 Collect Successful File System Mounts

os_arch=`getconf LONG_BIT` 

if [ $os_arch -eq 32 ]; then

echo -a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.22-Configuration to Collect Successful File System Mounts is configured in audit rules for 32 bit OS" >> /tmp/linuxreport.txt

else

echo -a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.22-Configuration to Collect Successful File System Mounts is configured in audit rules for 64 bit OS" >> /tmp/linuxreport.txt

fi

#3.11.23 Collect File Deletion Events by User

os_arch=`getconf LONG_BIT` 

if [ $os_arch -eq 32 ]; then


echo -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k delete >> /etc/audit/audit.rules

pkill -HUP auditd

echo "3.11.23-Configuration to Collect File Deletion Events by User is successfully configured in audit rules for 32 bit OS" >> /tmp/linuxreport.txt

else 

echo -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k delete >> /etc/audit/audit.rules

echo -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \ >> /etc/audit/audit.rules

echo -F auid!=4294967295 -k delete

pkill -HUP auditd 

echo "3.11.23-Configuration to Collect File Deletion Events by User is successfully configured in audit rules for 64 bit OS" >> /tmp/linuxreport.txt

fi

#3.11.24 Collect Changes to System Administration Scope (sudoers)

echo -w /etc/sudoers -p wa -k scope >> /etc/audit/audit.rules

pkill -HUP auditd 

echo "3.11.24-Configuration to Collect Changes to System Administration Scope (sudoers) in audit logs" >> /tmp/linuxreport.txt

#3.11.25Collect System Administrator Actions

echo -w /var/log/sudo.log -p wa -k actions >> /etc/audit/audit.rules

pkill -HUP auditd 

echo "3.11.24-Configuration to collect System Administrator Actions in audit logs is configured" >> /tmp/linuxreport.txt

#3.11.26 Collect Kernel Module Loading and Unloading

echo -w /sbin/insmod -p x -k modules >> /etc/audit/audit.rules

echo -w /sbin/rmmod -p x -k modules >> /etc/audit/audit.rules

echo -w /sbin/modprobe -p x -k modules >> /etc/audit/audit.rules

echo -a always,exit -S init_module -S delete_module -k modules >> /etc/audit/audit.rules

pkill -HUP auditd 

echo "3.11.26-Configuration to Collect Kernel Module Loading and Unloading in audit rules is configured" >> /tmp/linuxreport.txt


#3.11.27 Make the Audit Configuration Immutable

echo -e2 >> /etc/audit/audit.rules

echo "3.11.27-Audit configuration is made immutable" >> /tmp/linuxreport.txt

#3.11.28 Configure logrotate

ed /etc/logrotate.d/syslog << END
1d
0a
/var/log/messages /var/log/secure /var/log/maillog
/var/log/spooler /var/log/boot.log /var/log/cron {
.
w
q
END

echo "3.11.28-Logrotate for syslog is configured succesfully" >> /tmp/linuxreport.txt


####3.12 Secure System Access, Authentication & Authorization#######

#3.12.1 Enable cron Daemon

chkconfig cron on

if [ $? -eq 0 ]; then

echo "3.12.1-Cron daemon is enabled" >> /tmp/linuxreport.txt

else

echo "3.12.1-Enabling cron daemon is failed" >> /tmp/linuxreport.txt

fi

#3.12.2 Set User/Group Owner and Permission on /etc/crontab

chown root:root /etc/crontab

chmod og-rwx /etc/crontab

stat -c "%a %u %g" /etc/crontab | egrep ".00 0 0"

if [ $? -eq 0 ]; then

echo "3.12.2-User and Owner permission is configured for /etc/crontab" >> /tmp/linuxreport.txt

else

echo "3.12.2-User and Owner permission for /etc/crontab is failed" >> /tmp/linuxreport.txt

fi

#3.12.3 Set User/Group Owner and Permission on /etc/cron.hourly

chown root:root /etc/cron.hourly

chmod og-rwx /etc/cron.hourly


stat -c "%a %u %g" /etc/cron.hourly | egrep ".00 0 0"

if [ $? -eq 0 ]; then

echo "3.12.3-User and Owner permission is configured for /etc/cron.hourly" >> /tmp/linuxreport.txt

else

echo "3.12.3-User and Owner permission is failed for /etc/cron.hourly" >> /tmp/linuxreport.txt

fi

#3.12.5 Set User/Group Owner and Permission on /etc/cron.daily

chown root:root /etc/cron.daily

chmod og-rwx /etc/cron.daily

stat -c "%a %u %g" /etc/cron.daily | egrep ".00 0 0"

if [ $? -eq 0 ]; then

echo "3.12.5-User and Owner permission is configured for /etc/cron.daily" >> /tmp/linuxreport.txt

else "3.12.5-User and Owner permission is failed for /etc/cron.daily" >> /tmp/linuxreport.txt

fi

#3.12.6 Set User/Group Owner and Permission on /etc/cron.weekly

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

stat -c "%a %u %g" /etc/cron.weekly | egrep ".00 0 0"

if [ $? -eq 0 ]; then

echo "3.12.6-User and Owner permission is configured for /etc/cron.weekly" >> /tmp/linuxreport.txt

fi

#3.12.7 Set User/Group Owner and Permission on /etc/cron.monthly

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

stat -c "%a %u %g" /etc/cron.monthly | egrep ".00 0 0"


if [ $? -eq 0 ]; then

echo "3.12.7-User and Owner permission is configured for /etc/cron.monthly" >> /tmp/linuxreport.txt

fi

#3.12.8 Set User/Group Owner and Permission on /etc/cron.d


chown root:root /etc/cron.d

chmod og-rwx /etc/cron.d

stat -c "%a %u %g" /etc/cron.d | egrep ".00 0 0"

if [ $? -eq 0 ]; then

echo "3.122.8-User and Owner permission is configured for /etc/cron.d" >> /tmp/linuxreport.txt

fi

#3.12.10 Set SSH Protocol to 2

ssh_prot=`cat /etc/ssh/sshd_config |grep "#Protocol" |awk -F "," '{print $2}'`

if [ $ssh_prot -eq 1 ]; then

sed -i 's/#Protocol 2,1/Protocol 2/g' /etc/ssh/sshd_config

echo "3.12.10-ssh protocol2 is succesfully configured for this system" >> /tmp/linuxreport.txt

else

sed -i 's/Protocol 2,1/Protocol 2/g' /etc/ssh/sshd_config

echo "3.12.10-ssh protocol is changed from 2,1 to 2" >> /tmp/linuxreport.txt
fi

#3.12.11 Set LogLevel to VERBOSE

sed -i 's/#LogLevel INFO /LogLevel VERBOSE/g'  /etc/ssh/sshd_config

echo "3.12.11-ssh LogLevel to VERBOSE is successfully configured" >> /tmp/linuxreport.txt

#3.12.11 Set Permissions on /etc/sshd_config

chown root:root /etc/ssh/sshd_config

chmod 644 /etc/ssh/sshd_config

stat -c "%a %u %g" /etc/ssh/sshd_config | egrep ".00 0 0"

if [ $? -eq 0 ]; then

echo "3.12.11-User and Owner permission is configured for /etc/ssh/sshd_config" >> /tmp/linuxreport.txt

fi

#3.12.13 Set SSH MaxAuthTries to 5 or Less

sed -i 's/#MaxAuthTries 6/MaxAuthTries 5/g'  /etc/ssh/sshd_config

echo "3.12.13-ssh MaxAuthTries configured sucessfully" >> /tmp/linuxreport.txt

#3.12.15 Set SSH HostbasedAuthentication to No

sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g'  /etc/ssh/sshd_config

echo "3.12.15-Disabled HostbasedAuthentication in ssh" >> /tmp/linuxreport.txt

###################################################################
##Adding Alternate user in the system

read -p "Enter username : " username
read -s -p "Enter password : " password
egrep "^$username" /etc/passwd >/dev/null
if [ $? -eq 0 ]; then
echo "$username exists!"
exit 1
else
pass=$(perl -e 'print crypt($ARGV[0], "password")' $password)
useradd -m -p $pass $username
echo "user '$username' is added in the system"
fi
#3.12.16 Disable SSH Root Login

ssh_root=`cat /etc/ssh/sshd_config |grep "#PermitRootLogin"|awk -F " " '{print $2}'`

if [ "$ssh_root" == "yes" ]; then

sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g'  /etc/ssh/sshd_config

echo "3.12.16-root login is diabled for this server" >> /tmp/linuxreport.txt
fi
                           
#3.12.17 Set SSH PermitEmptyPasswords to No

empty_pass=`cat /etc/ssh/sshd_config |grep "#PermitEmptyPasswords"|awk -F " " '{print $2}'`

if [ "empty_pass" == "no" ]; then 

sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

echo " 3.12.17-ssh PermitEmptyPasswords is diabled for this system" >> /tmp/linuxreport.txt

fi 

##3.12.18 Use Only Approved Ciphers

echo Ciphers aes128-ctr,aes192-ctr,aes256-ctr >> /etc/ssh/sshd_config

echo " 3.12.18-Ciphers are updated in ssh" >> /tmp/linuxreport.txt

#3.12.20 Set SSH Banner

cat << EOF >> /etc/issue

************************************************************NOTICE***ONMOBILE SECURITY POLICY****************************************************************
WARNING! This is an OnMobile Global computer system and may be accessed only by authorized users. OnMobile Global computer systems are provided for business purposes and must be used in an ethical lawful manner. All data contained here is owned by OnMobile Global Ltd., and may be monitored, examined, intercepted, blocked, deleted, captured and disclosed in any manner, by authorized personnel. Individuals or groups using this system in excess of their authorization will have all access terminated. Unauthorized use or misuse of this system is strictly prohibited and may be subject to disciplinary action.
**************************************************************NOTICE***ONMOBILE SECURITY POLICY******************************************************
EOF



cat /etc/ssh/sshd_config |grep "#Banner"

if [ $? -eq 0 ]; then

sed -i 's/Banner/#Banner/g' /etc/ssh/sshd_config 

echo Banner /etc/issue >> /etc/ssh/sshd_config

echo " 3.12.20-Banner is configured successfuly for this system" >> /tmp/linuxreport.txt

fi


###3.12.21 Configure PAM

grep "^password.*pam_cracklib.so.*" /etc/pam.d/system-auth

if [ $? -eq 0 ]; then

sed -i 's/^password.*requisite.*pam_cracklib.so.*/password    required      pam_cracklib.so try_first_pass retry=3 minlen=14,dcredit=-1,ucredit=-1,ocredit=-1 lcredit=-1/g' /etc/pam.d/system-auth


echo " 3.12.21-PAM is configured sucessfully " >> /tmp/linuxreport.txt

fi

####3.12.22 Set Strong Password Creation Policy Using pam_passwdqc

grep  "^password.*pam_passwdqc.so.*" /etc/pam.d/system-auth

if [ $? -eq 0 ]; then

sed -i 's/^password.*requisite.*pam_passwdqc.so.*/password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8/g' /etc/pam.d/system-auth

echo "3.12.22-Strong password creation policy is configured sucessfully" >> /tmp/linuxreport.txt

fi

###3.12.24 Upgrade Password Hashing Algorithm to SHA-512

authconfig --test |grep  "hashing" |grep  "sha512" 

if [ $? -eq 0 ]; then

echo "3.12.24-Password hashing algorithm is already avilable in this system" >> /tmp/linuxreport.txt

else

authconfig --passalgo=sha512 --update

authconfig --test | grep hashing | grep sha512

if [ $? -eq 0 ]; then 

echo "3.12.24-Hashing Algorithm is upgraded sucessfully" >> /tmp/linuxreport.txt

fi
fi

###3.12.25 Limit Password Reuse

grep "password.*pam_unix.so.*" /etc/pam.d/system-auth

if [ $? -eq 0 ]; then

sed -i 's/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=3/g' /etc/pam.d/system-auth

fi

echo "3.12.25-Limit password reuse is configured sucessfully" >> /tmp/linuxreport.txt




###3.13.2 Set Password Expiration Days

sed -i 's/PASS_MAX_DAYS/#PASS_MAX_DAYS/g' /etc/login.defs

echo PASS_MAX_DAYS 90 >> /etc/login.defs

chage --maxdays 90 omadmin

echo "3.13.2-Password expiration date is configured sucessfully" >> /tmp/linuxreport.txt

####3.13.3 Set Password Change Minimum Number of Days

sed -i 's/PASS_MIN_DAYS/#PASS_MIN_DAYS/g' /etc/login.defs

echo PASS_MIN_DAYS 7 >> /etc/login.defs

chage --mindays 7 omadmin

echo "3.13.3-Password change minimum number of days is configured sucessfully" >> /tmp/linuxreport.txt

###3.13.5 Set Default Group Account (root)

usermod -g 0 root

grep root /etc/passwd | awk -F ":" '{print $4}'

if [ $? -eq 0 ]; then

echo "3.13.5-Default Group Account is set for root" >> /tmp/linuxreport.txt

fi

#####################################################################################################################
#3.13.8 Set Warning Banner for Standard Login Services

cat /etc/motd |grep "OnMobile Global"

if [ $? -ne 0 ]; then

echo "This is an OnMobile Global computer system. Authorized uses only. All activity may be monitored and reported." >> /etc/motd
 
echo "This is an OnMobile Global computer system. Authorized uses only. All activity may be monitored and reported." >> /etc/issue

chown root:root /etc/motd
chown root:root /etc/issue
chmod 644 /etc/motd
chmod 644 /etc/issue

echo "3.13.8-Warning Banner is configured" >> /tmp/linuxreport.txt

else

echo "3.13.8-Warning Banner is already configured" >> /tmp/linuxreport.txt

fi

#######################################################################################################################






















































 




























 





















 















 





 
 


 








