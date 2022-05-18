#!/bin/bash
#version 6
LIBCHK=psmpparms.sample
VLTFILE=stvlt.chk
PSMPENVFILE=psmpenv.chk
VERSION_PSMP="v12.5" # UPDATE THIS (This is just for UI sake, it doesn't impact anything in the script)
PSMPLOGS=psmplogs.chk

#static
psmpparms="/var/tmp/psmpparms"
psmpparmstmp="/var/tmp/psmpparmstmp"
psmpwizerrorlog="_psmpwizerror.log"

#filenames (because package is different than actual file) - this goes with every -ivh/Uvh command
newVersionFile="CARKpsmp-12.05.0.33.x86_64.rpm"
newLibSSHFile="libssh-0.9.4.x86_64.rpm"
newIntergratedInfraFile="CARKpsmp-infra-12.05.0.33.x86_64.rpm"

#packagenames (this goes with every -qa command)
newVersion="CARKpsmp-12.05.0-33.x86_64" #UPDATE this to the latest version always (It's usually diff than the .rpm file we define above, it has dash instead of dot.)
currVersion=`rpm -qa | grep CARKpsmp-1` #this grabs only CARKpsmp because of the "-1" (ie 11.05, 12.01, 12.02) to get accurate single package return
package_to_remove=`rpm -qa | grep CARKpsmp` #this grabs both CARKpsmp and Infra, to make sure we delete everything.

#Check for SUSE
if [[ `cat /etc/os-release | grep -i suse` ]]
then
        echo "****** Detected SUSE os under: /etc/os-release"
        echo "****** The script unfortunately doesn't support SUSE yet :("
        exit 1
fi

#Functions
PVWAAUTH(){
read -r -p "*****(Optional) Would you like to validate the entered credentials? this will require you to input your Privilege Cloud Portal URL & Make sure FW is open on 443 [Y/N] " response
if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
	then
		read -r -p "Please enter your Privilege Cloud Portal URL: " pvwaURL
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		
		#Check if URL belongs to UM env, otherwise use legacy.
		if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
			pvwaURLAPI=https://$TrimHTTPs.cyberark.cloud/api/passwordvault/Auth/CyberArk/Logon
		else
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api/Auth/CyberArk/Logon
		fi
		echo "Making API call to: " $pvwaURLAPI
		echo "Will timeout in 20s if doens't reach Portal on 443..."

rest=$(curl --location -k -m 40 --connect-timeout 20 -o /dev/null -s --request POST --w "%{http_code}" "$pvwaURLAPI" \
--header "Content-Type: application/json" \
--data @<(cat <<EOF
{
	"username": "$adminuser",
	"password": "$adminpass",
	"concurrentSession": "false"
}
EOF
))

		echo "HTTP Return Code: " $rest

		if [[ $rest == 200 ]]; then
		echo "Validation Passed!"
		else 
			read -r -p "***** Validation Failed, do you want to continue anyway? [Y/N] " response
			if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
				then
					echo "Cred Validation - skipped"
				else
					echo "***** Make sure the username and password are correct and try again."			
					exit 1
			fi
			
		fi
	else
	echo "Cred Validation - skipped"
fi
}

editPsmpparms(){
	\cp psmpparms.sample $psmpparms
	echo "***** Updating the psmpparms file *****"
	sed -i 's|AcceptCyberArkEULA=No|AcceptCyberArkEULA=Yes|g' $psmpparms
	awk '{sub(/InstallationFolder=<Folder Path>/,"InstallationFolder='"$PWD"/'")}1' $psmpparms > $psmpparmstmp && mv $psmpparmstmp $psmpparms && rm -rf $psmpparmstmp
	sed -i 's|InstallCyberArkSSHD=Yes|InstallCyberArkSSHD=Integrated|g' $psmpparms
	sed -i 's|#EnableADBridge=Yes|EnableADBridge=No|g' $psmpparms
}

errorLogsPrint(){
echo "***** Error: Failed to install RPM. Fix the errors and rerun wizard again."
installlogs=("$PWD"/"$psmpwizerrorlog" "/var/tmp/psmp_install.log" "/var/opt/CARKpsmp/temp/EnvManager.log")

printonce="1"
for n in ${installlogs[@]}
do
        if [ -s $n ] #check file not empty
        then
						#make sure to print this line only once for the whole loop.
                        if [[ $printonce -eq 1 ]]
                        then
                                echo "***** Useful Logs:"
                                printonce=2
                        fi
				#file is not empty so we print it
                echo "***** $n"
        fi
done
}

if [ "$EUID" -ne 0 ]; then
  read -p "***** Please run as root - Press ENTER to logout..."
  exit
fi

if [ ! -f "$LIBCHK" ]; then
  echo "***** Please run the script from the PSMP installation folder"
  read -p "***** - Press ENTER to continue..."
  exit 1
fi

clear
echo "--------------------------------------------------------------"
echo "-----------CyberArk PSMP Installation Wizard ($VERSION_PSMP)-----------"
echo "--------------------------------------------------------------"

########################################################################################
#------------------------------------Check Previous PSMP------------------------------#
########################################################################################

#check if previous version is installed and only then compare with new version and suggest upgrade
if [ -z "$currVersion" ]
then
	echo "No previous version installed, proceeding with fresh install"
else 
        if [[ $newVersion > $currVersion ]]
		then	
			echo "old $currVersion"
            echo "new $newVersion"
			read -r -p "***** Found an older version, would you like to upgrade? [Y/N] " response
			if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]] 
			then
				################################### psmpparms
				editPsmpparms
				################################## cred file
				echo "***** CredFile Creation *****"
				chmod 755 CreateCredFile
				echo " "
				read -p "Please Enter Privilege Cloud Install Username: " adminuser
				echo " "
				echo "***** Please Enter Privilege Cloud Install User Password and press ENTER *****"
				read -s adminpass
					if [ -z "$adminpass" ]
						then
						echo "password is empty, rerun script"
						exit
					else
						adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
					fi
				PVWAAUTH # PVWA CHECK
				sleep 8
				./CreateCredFile user.cred Password -Username $adminuser -Password $adminpw -EntropyFile
				echo ""
				echo "'"
				#Upgrade command
				rpm --import RPM-GPG-KEY-CyberArk
				rpm -Uvh ./IntegratedMode/$newIntergratedInfraFile &> $psmpwizerrorlog
				sleep 2
				echo ""
				rpm -Uvh $newVersionFile &> $psmpwizerrorlog
				sleep 1
				echo ""
				################################## Delete user.cred
				echo ""
				echo "***** Clearing Credentials *****"
				rm -rf user.cred
				sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv.service
				sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv-psmpserver.service
				sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv-psmpadbserver.service
				systemctl daemon-reload
				systemctl restart psmpsrv.service
				systemctl status psmpsrv.service
				exit
			else
				exit
			fi
		else
		if rpm -qa | grep -q $newVersion; then
			read -r -p "***** PSMP Already installed, would you like to Repair/Uninstall? [Y/N] " response
			if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]] 
			then
				read -r -p "***** Type 'R' to Repair or 'U' to Uninstall: " response
				if [[ $response =~ ^([rR|[rR])$ ]]
				then
					################################### psmpparms
					editPsmpparms
					################################## cred file
					echo "***** CredFile Creation *****"
					chmod 755 CreateCredFile
					echo " "
					read -p "Please Enter Privilege Cloud Install Username: " adminuser
					echo " "
					echo "***** Please Enter Privilege Cloud Install Username Password and press ENTER *****"
					read -s adminpass
					if [ -z "$adminpass" ]
						then
						echo "password is empty, rerun script"
						exit
					else
						adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
					fi
					PVWAAUTH # PVWA CHECK
					sleep 8
					./CreateCredFile user.cred Password -Username $adminuser -Password $adminpass -EntropyFile
					echo ""
					echo ""
					rpm -Uvh --force $newVersionFile  &> $psmpwizerrorlog #Repair
					sleep 1
					echo ""
					################################## Delete user.cred
					echo ""
					echo "***** Clearing Credentials *****"
					rm -rf user.cred
					
					sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv.service
					sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv-psmpserver.service
					sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv-psmpadbserver.service
					systemctl daemon-reload
					systemctl restart psmpsrv.service
					systemctl status psmpsrv.service
					
					exit
				fi
					if [[ $response =~ ^([uU|[uU])$ ]]
					then 
						rpm -e $package_to_remove	
						sleep 1
						exit
					fi
					else exit 
			fi 
					fi
		fi
fi


########################################################################################
#------------------------------------System Prerequisites------------------------------#
########################################################################################
if [ ! -f "$SYSPRP" ]; then
#placeholder
echo ""
fi


########################################################################################
#---------------------------------------------- PSMP Installation Wizard---------------#
########################################################################################
if [ ! -f "$VLTFILE" ]; then
################################### VaultIP
a=0
while [ $a -lt 1 ]
do
echo ""
read -p "Insert Vault Address: " vaultip
echo "---------------------------------"
echo "***** Vault Configuration: ******"
echo "** Vault Address: $vaultip "
read -r -p "***** Please confirm: [Y/N] " response
if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "***** Done..."
    a=`expr $a + 1`
else
 echo "Please Try Again..."
fi
done

################################### Connectivity test
#save connection output to file
rm -rf /tmp/capture.out
cap () { tee /tmp/capture.out; }

echo "***** Connectivity test *****"
echo ""
read -r -p "***** Do you want to perform connectivity test to: $vaultip [Y/N] " response
if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "***** Waiting for Vault response..."
		timeout 3 bash -c '</dev/tcp/'$vaultip'/1858' && echo port is open | cap || echo port is closed | cap
		ret=$(cat /tmp/capture.out) #get result from connection test
		clear
		if [[ "echo $ret" == *"open"* ]];
		then 
			echo "***** Connectivity test - *** PASSED ***"
		else
			echo "***** Connectivity test - *** FAILED ***"
			echo "***** Recommendation: check your network configuration and re-run the installation script"	
			read -r -p "***** Do you want to continue anyway? to: $vaultip [Y/N] " response
				if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
					then
						echo "Connectivity test - skipped"
					else
						echo "***** Please check your network configuration and re-run the installation script"			
						exit 1
				fi
  	
	fi
else
 echo "Connectivity test - skipped"
fi


################################### Vault.ini
sed -i "s/1.1.1.1/"$vaultip"/g" vault.ini
echo "vault.ini updated" > stvlt.chk
fi

################################### psmpparms
editPsmpparms

echo ""
echo ""
sleep 2
clear


################################## cred file
echo "***** CredFile Creation *****"
chmod 755 CreateCredFile
echo " "
read -p "Please Enter Privilege Cloud Install Username: " adminuser
echo " "
echo "***** Please Enter Privilege Cloud Install Username Password and press ENTER *****"
read -s adminpass
	if [ -z "$adminpass" ]
	then
        echo "password is empty, rerun script"
		exit
	else
        adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
	fi
PVWAAUTH # PVWA CHECK
sleep 8
./CreateCredFile user.cred Password -Username $adminuser -Password $adminpw -EntropyFile
echo ""
echo ""



################################### rpm installation
echo "***** Primary RPM Installation, This may take some time...*****"
rpm --import RPM-GPG-KEY-CyberArk
rpm -ivh ./IntegratedMode/$newIntergratedInfraFile &> $psmpwizerrorlog
	if [[ `rpm -qa | grep CARKpsmp-i` ]]
	then 
		echo "RPM package install succesful."
	else
		errorLogsPrint
		exit 1
	fi
echo ""
sleep 2
rpm -ivh $newVersionFile &> $psmpwizerrorlog
	if [[ `rpm -qa | grep CARKpsmp-1` ]]
	then 
		echo "RPM package install succesful."
	else
		errorLogsPrint
		exit 1
	fi

clear
echo ""
#add https to docs page, this is a bug in 12.1.1, it's already fixed in 12.2 and is just annoying when running status command, so lets manually fix it.
sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv.service
sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv-psmpserver.service
sed -i 's|docs.cyberark.com|https://docs.cyberark.com|g' /usr/lib/systemd/system/psmpsrv-psmpadbserver.service

systemctl daemon-reload
systemctl restart psmpsrv.service
systemctl status psmpsrv.service
sleep 2



########################################################################################
#--------------------------------------Post Installation ------------------------------#
########################################################################################

################################## Selinux Integrated config
echo ""
echo "***** Applying Selinux in integrated mode *****"
semodule -i /etc/opt/CARKpsmp/selinux/psmp_integrated_rhel7.pp

################################## Delete user.cred
echo ""
echo "***** Clearing Credentials *****"
rm -rf user.cred


################################## Create Automatic Log rotation 
echo ""
if [ ! -f "$PSMPLOGS" ]; then
echo "***** Creating Log rotation mechanism *****"
mkdir /var/opt/CARKpsmp/logs/archive
cat <<'EOF' > /var/opt/CARKpsmp/logs/archive/logCleaner.sh
declare -a dirs=("/var/opt/CARKpsmp/logs/old" "/var/opt/CARKpsmpadb/logs/old")

for d in "${dirs[@]}"
do
        random_string=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
        find $d -name "*.log" -mtime +30 -print | xargs tar -czvPf plogs_${random_string}.tar.gz -C $d
        find $d -name "*.log" -mtime +30 -print -exec rm {} \;
done

for d in "${dirs[@]}"
do
        find $d -name "plogs_*" -mtime +183 -exec rm {} \;
done
EOF
sleep 2

chmod 755 /var/opt/CARKpsmp/logs/archive/logCleaner.sh

################################## Create CronJob 
echo ""
echo "***** Creating Cronjob task to run Log rotation mechanism daily at 04:00 *****"
crontab -l | { cat; echo "0 4 * * * /var/opt/CARKpsmp/logs/archive/logCleaner.sh"; } | crontab -
echo "psmplogs" > psmplogs.chk
fi


echo ""
echo "*************************************************************"
echo "---- PSMP Installation Wizard Was Completed ----"
echo "*************************************************************"