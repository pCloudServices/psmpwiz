#!/bin/bash
###########################################################################
#
# NAME: CyberArk Privilege Cloud PSMP Install Helper
#
# AUTHOR:  Mike Brook <mike.brook@cyberark.com>
#
# COMMENT: 
# This script wraps the PSMP RPM package and helps guide you through installation process.
#
###########################################################################
LIBCHK=psmpparms.sample
VLTFILE=stvlt.chk
PSMPENVFILE=psmpenv.chk
VERSION_PSMP="v12.6" # UPDATE THIS (This is just for UI sake, it doesn't impact anything in the script)
PSMPLOGS=psmplogs.chk

#colors
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'

#static
psmpparms="/var/tmp/psmpparms"
psmpparmstmp="/var/tmp/psmpparmstmp"
psmpwizerrorlog="_psmpwizerror.log"
#github
scriptVersion="1" #update this locally and github.
scriptFileName="psmpwiz1260.sh"
masterBranch="https://raw.githubusercontent.com/pCloudServices/psmpwiz/master"
checkVersion="$masterBranch/LatestPSMP1260.txt" #update this in github
newScriptVersion="$masterBranch/$scriptFileName" #update this locally

#filenames (because package is different than actual file) - this goes with every -ivh/Uvh command
newVersionFile="CARKpsmp-12.06.0.26.x86_64.rpm"
newLibSSHFile="libssh-0.9.4.x86_64.rpm"
newIntergratedInfraFile="CARKpsmp-infra-12.06.0.26.x86_64.rpm"

#packagenames (this goes with every -qa command)
newVersion="CARKpsmp-12.06.0-26.x86_64.rpm" #UPDATE this to the latest version always (It's usually diff than the .rpm file we define above, it has dash instead of dot.)
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
testGithubVersion(){
echo "***** Checking latest version on Github..."
echo "***** If this takes long time (DNS resolve), you can run the script with the flag -skip to skip this check...."
getVersion=`curl --max-time 3 -s $checkVersion`

if [[ $getVersion ]]; then
	echo "***** Script version is: $scriptVersion"
	echo "***** Latest version is: $getVersion"
	sleep 2
else
	echo "***** Couldn't reach github to check for latest version, that's ok! skipping..."
	sleep 2
fi 
if [[ $getVersion -gt $scriptVersion ]]; then
        echo "***** Found a newer version!"
        echo "***** Replacing current script with newer script"
        mv $0 $0.old #move current to old
        echo "***** Downloading new version from Github"
        curl -s $newScriptVersion -o $scriptFileName # -s hides output
		chmod 755 $scriptFileName
        echo "***** Done, relaunch the script."
        exit 1
fi
}

#PVWA Calls
pvwaLogin(){
rest=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w " %{http_code}" "$pvwaURLAPI/Auth/CyberArk/Logon" \
--header "Content-Type: application/json" \
--data @<(cat <<EOF
{
	"username": "$adminuser",
	"password": "$adminpass",
	"concurrentSession": "false"
}
EOF
))
}

pvwaLogoff(){
pvwaActivate=$(curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Auth/Logoff" \
--header "Content-Type: application/json" \
--header "Authorization: $pvwaHeaders" \
)
}

pvwaGetUserId(){
pvwaGetUser=$(curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/Users?filter=componentUser\&search=$credUsername" \
--header "Content-Type: application/json" \
--header "Authorization: $pvwaHeaders" \
)
}

pvwaActivateUser(){
pvwaActivate=$(curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Users/$userID/Activate" \
--header "Content-Type: application/json" \
--header "Authorization: $pvwaHeaders" \
)
}

pvwaResetPW(){
pvwaReset=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w " %{http_code}" "$pvwaURLAPI/Users/$userID/ResetPassword" \
--header "Content-Type: application/json" \
--header "Authorization: $pvwaHeaders" \
--data @<(cat <<EOF
{
	"id": "$userID",
	"newPassword": "$randomPW",
	"concurrentSession": "false"
}
EOF
))
}

pvwaSystemHealthUser(){
pvwaSystemHealth=$(curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/ComponentsMonitoringDetails/SessionManagement" \
--header "Content-Type: application/json" \
--header "Authorization: $pvwaHeaders" \
)
}


PVWAAUTH(){
read -r -p "*****(Optional) Would you like to validate the entered credentials? this will require you to input your Privilege Cloud Portal URL & Make sure FW is open on 443 [Y/N] " response
if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
	then
		read -r -p "Please enter your Privilege Cloud Portal URL: " pvwaURL
		extractSubDomainFromURL=${pvwaURL%%.*}
		TrimHTTPs=${extractSubDomainFromURL#*//}
		
		#Check if URL belongs to UM env, otherwise use legacy.
		if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
			pvwaURLAPI=https://$TrimHTTPs.cyberark.cloud/api/passwordvault
		else
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
		fi
		echo "Making API call to: " $pvwaURLAPI
		echo "Will timeout in 20s if doens't reach Portal on 443..."
		#call login
		pvwaLogin
		if  [[ `echo $rest | grep "200"` ]]; then
		echo -e "${GREEN}Validation Passed!${NC}"
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

creds(){
read -p "Please Enter Privilege Cloud Install Username: " adminuser
echo " "
echo "***** Please Enter Privilege Cloud Install User Password and press ENTER *****"
read -s adminpass
	if [ -z "$adminpass" ]
		then
		echo "password is empty, rerun script"
		exit 1
	else
		adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
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
echo -e "*****${RED} Error: Failed to install RPM. Fix the errors and rerun wizard again.${NC}"
installlogs=("$PWD"/"$psmpwizerrorlog" "$PWD/psmp_install.log" "$PWD/EnvManager.log")

#copy logs to centralized dir
\cp /var/tmp/psmp_install.log psmp_install.log
\cp /var/opt/CARKpsmp/temp/EnvManager.log EnvManager.log

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
		else
			#delete the files copied, less clutter.
			rm -rf $n
        fi
done
}

resetCredFile(){
#files
pspmpcredfiles=("/etc/opt/CARKpsmp/vault/psmpappuser.cred" "/etc/opt/CARKpsmp/vault/psmpgwuser.cred")
pvconfigurationFile="/var/opt/CARKpsmp/temp/PVConfiguration.xml"
createcredfile="/opt/CARKpsmp/bin/createcredfile"
clear
echo "***** To perform this task we must be able to reach your cloud portal (ie; https://mikeb.privilegecloud.cyberark.cloud) via HTTPS/443."
echo ""
read -r -p "***** Do you want to continue? [Y/N] " response
if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]];then
		echo "***** Selected YES..."
		#grab pvwa url
		echo "***** Grabbing PVWA URL from: $pvconfigurationFile"
			if [ -s $pvconfigurationFile ]; then
				pvwaURL=`cat $pvconfigurationFile | grep -oP '(?<=ApplicationRoot=").*?(?=")'`
				echo -e "***** PVWA URL is: ${GREEN}$pvwaURL${NC}"
				extractSubDomainFromURL=${pvwaURL%%.*}
				TrimHTTPs=${extractSubDomainFromURL#*//}
				if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
					pvwaURLAPI=https://$TrimHTTPs.cyberark.cloud/api/passwordvault
				else
					pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
				fi
			else
				read -r -p "couldn't grab PVWA URL, please enter it manually (ie; https://mikeb.privilegecloud.cyberark.cloud)." pvwaURL
				extractSubDomainFromURL=${pvwaURL%%.*}
				TrimHTTPs=${extractSubDomainFromURL#*//}
				#Check if URL belongs to UM env, otherwise use legacy.
				if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
					pvwaURLAPI=https://$TrimHTTPs.cyberark.cloud/api/passwordvault
				else
					pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
				fi
			fi
						#PVWA Login
						echo "***** Establishing connection to PVWA..."
						# pvwaURLAPI=$pvwaURL/api # Uncomment this if you're using onprem PAS.
						echo "***** Calling: " $pvwaURLAPI
						creds # get user input
						pvwaLogin #call login
						if  [[ `echo $rest | grep "200"` ]]; then
							echo -e "*****${GREEN} Connected!${NC}"
							# grab headers
							pvwaHeaders=`echo $rest | cut -d' ' -f1 | tr -d '"'`
						else
							echo -e "***** ${RED}Connection failed...${NC}"
							echo $rest
							echo -e "***** ${RED}Unable to proceed, fix connection to PVWA and rerun the script.${NC}"
							exit 1
						fi
		
			for n in ${pspmpcredfiles[@]} #both app and gw
				do
					echo "***** Generating CredFile: $n"
					if [ -s $n ]; then  #check file not empty
						credUsername=`cat $n | grep -oP '(?<=Username=).*(?=)'`
						echo -e "***** Grabbed username: ${PURPLE}$credUsername${NC}"
						#generate random temp pw from 2 methods and combine them to create a strong pw.
						randomPW1=`tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo ''`
						randomPW2=`date | md5sum` && randomPWtrim=`echo $randomPW2 | cut -d' ' -f1`
						randomPW="${randomPW1}${randomPWtrim::-27}" #-27 to avoid the 39 char limit and repeating chars.
						$createcredfile $n Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
						#get user ID
						echo "***** Retrieving UserID for user $credUsername"
						pvwaURLAPI=$pvwaURL/api #not sure about this in the final version.
						pvwaGetUserId
						userID=`echo $pvwaGetUser | grep -oP '(?<="id":).*?(?=,)'` # grabs user id
						echo "***** userID: $userID"
						echo "***** Activating/Unsuspending user: $credUsername just in case."
						pvwaActivateUser
						sleep 1
							if [[ $pvwaActivate == 200 ]]; then
								echo -e "***** ${GREEN}Successfully Activated: $credUsername${NC}"
							else
								echo -e "***** ${RED}Failed Activating: $credUsername${NC}"
								echo $pvwaActivate
								exit 1
							fi
						echo "***** Resetting Password user: $credUsername"
						pvwaResetPW # call reset pw
						sleep 1
							if [[ `echo $pvwaReset | grep "200"` ]]; then
								echo -e "***** ${GREEN}Successfully Restet Password: $credUsername${NC}"
							else
								echo -e "***** ${RED}Failed Resetting Password: $credUsername${NC}"
								echo $pvwaReset
								exit 1
							fi
					else
						echo "***** File is empty or corrupted, aborting..."
						exit 1
					fi
				done
				
				echo "***** Restarting PSMP Service..."
				systemctl daemon-reload
				systemctl restart psmpsrv.service
				systemctl status psmpsrv.service
				sleep 5
				echo "***** Checking to see if service is back online via SystemHealth."
				pvwaSystemHealthUser
				# grab only relevant username and cut everything except IsLoggedOn "true" or "false"
				appName=`echo $credUsername | cut -d'_' -f2` #better to search the exact name instead of with app/gw prefix.
				status=`echo $pvwaSystemHealth | grep -oP "($appName).*?(?="LastLogonDate")" | grep -oP '(?<="IsLoggedOn":).*?(?=,)'`
				if [[ `echo $status | grep "true"` ]];then 
					echo -e "***** ${GREEN}$appName Is : Online!${NC}"
				else
					echo -e "***** ${RED}$appName Is : Offline!${NC}"
					echo -e "***** ${RED}Return call was: $status${NC}"
					echo -e "***** Something went wrong :( you'll have to reset it manually with CyberArk's help."
					exit
				fi
				# Logoff
				pvwaLogoff
exit 1
						
else
	echo "***** Selected NO..."
	echo "***** Exiting..."
	exit 1
fi

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
echo "----------- CyberArk PSMP Installation Wizard ($VERSION_PSMP) --------"
echo "----------- psmpwiz script version "$scriptVersion" -------------------------"
echo "--------------------------------------------------------------"

########################################################################################
#------------------------------------Check Previous PSMP------------------------------ #
########################################################################################
# skip new version
while test $# -gt 0; do
  case "$1" in
    -skip*)
		testGithubVersion(){ echo "***** Skipped online version check." ; } #nullify the function so its not called out down the road.
      shift
      ;;
    *)
		# Placeholder for future flags
      break
      ;;
  esac
done
# Get new version from github
testGithubVersion



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
				creds # user input creds
				PVWAAUTH # PVWA CHECK
				sleep 8
				./CreateCredFile user.cred Password -Username $adminuser -Password $adminpw -EntropyFile
				echo ""
				echo "'"
				#Upgrade command
				rpm --import RPM-GPG-KEY-CyberArk
				rpm -Uvh ./IntegratedMode/$newIntergratedInfraFile &> $psmpwizerrorlog
					#check if package is installed and if log file contains error.
					if [[ `rpm -qa | grep CARKpsmp-i` ]] && [[ ! `cat $psmpwizerrorlog | grep error` ]]
					then 
						echo -e "${GREEN}RPM package install successful: $newIntergratedInfraFile${NC}"
					else
						errorLogsPrint
						echo "***** Clearing Credentials *****"
						rm -rf user.cred
						exit 1
					fi
				sleep 2
				echo ""
				rpm -Uvh $newVersionFile &> $psmpwizerrorlog
					if [[ `rpm -qa | grep CARKpsmp-1` ]] && [[ ! `cat $psmpwizerrorlog | grep error` ]]
					then 
						echo -e "${GREEN}RPM package install successful: $newVersionFile${NC}"
					else
						errorLogsPrint
						echo "***** Clearing Credentials *****"
						rm -rf user.cred
						exit 1
					fi
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
			read -r -p "***** PSMP Already installed, would you like to Repair/ResetCred/Uninstall? [Y/N] " response
			if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]] 
			then
				read -r -p "***** Type 'R' to Repair ||| 'U' to Uninstall ||| 'C' to ResetCred " response
				if [[ $response =~ ^([rR|[rR])$ ]]
				then
					################################### psmpparms
					editPsmpparms
					################################## cred file
					echo "***** CredFile Creation *****"
					chmod 755 CreateCredFile
					echo " "
					creds # user input creds 
					PVWAAUTH # PVWA CHECK
					sleep 8
					./CreateCredFile user.cred Password -Username $adminuser -Password $adminpass -EntropyFile
					echo ""
					echo ""
					echo "***** Start repair, this may take some time..."
					rpm -Uvh --force $newVersionFile  &> $psmpwizerrorlog #Repair
						if [[ ! `cat $psmpwizerrorlog | grep error` ]]
						then 
							echo "RPM package install successful: $newVersionFile"
						else
							errorLogsPrint
							echo "***** Clearing Credentials *****"
							rm -rf user.cred
							exit 1
						fi
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
					if [[ $response =~ ^([uU|[uU])$ ]];then 
						rpm -e $package_to_remove	
						sleep 1
						exit
					fi
					if [[ $response =~ ^([cC|[cC])$ ]];then
						resetCredFile
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
creds # user input creds
PVWAAUTH # PVWA CHECK
sleep 8
./CreateCredFile user.cred Password -Username $adminuser -Password $adminpw -EntropyFile
echo ""
echo ""



################################### rpm installation
echo "***** Primary RPM Installation, This may take some time...*****"
rpm --import RPM-GPG-KEY-CyberArk
echo "***** Installing: $newIntergratedInfraFile"
rpm -ivh ./IntegratedMode/$newIntergratedInfraFile &> $psmpwizerrorlog
	if [[ `rpm -qa | grep CARKpsmp-i` ]] && [[ ! `cat $psmpwizerrorlog | grep error` ]] #package must be installed and no errors in log
	then 
		echo "***** RPM package install successful: $newIntergratedInfraFile"
	else
		errorLogsPrint
		echo ""
		echo "***** Let's uninstall RPM packages since installation was not completed. *****"
		del=`rpm -qa | grep CARKpsmp` && rpm -e $del --quiet
		echo "***** Clearing Credentials *****"
		rm -rf user.cred
		exit 1
	fi
echo ""
sleep 2
echo "***** Installing: $newVersionFile"
rpm -ivh $newVersionFile &> $psmpwizerrorlog
	if [[ `rpm -qa | grep CARKpsmp-1` ]] && [[ ! `cat $psmpwizerrorlog | grep error` ]]
	then 
		echo "***** RPM package install successful: $newVersionFile"
	else
		errorLogsPrint
		echo ""
		echo "***** Let's uninstall RPM packages since installation was not completed. *****"
		del=`rpm -qa | grep CARKpsmp` && rpm -e $del --quiet
		echo "***** Clearing Credentials *****"
		rm -rf user.cred
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