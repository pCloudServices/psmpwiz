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
VERSION_PSMP="v13.1" # UPDATE THIS (This is just for UI sake, it doesn't impact anything in the script)
PSMPLOGS=psmplogs.chk

#colors
GREEN='\033[0;32m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'
YELLOW='\033[0;33m'

#static
psmpparms="/var/tmp/psmpparms"
psmpparmstmp="/var/tmp/psmpparmstmp"
psmpwizerrorlog="_psmpwizerror.log"
#github
scriptVersion="1" #update this locally and github.
scriptFileName="psmpwiz1310.sh" #update this locally
masterBranch="https://raw.githubusercontent.com/pCloudServices/psmpwiz/master"
checkVersion="$masterBranch/LatestPSMP1310.txt" #update this in github
newScriptVersion="$masterBranch/$scriptFileName" 

#filenames (because package is different than actual file) - this goes with every -ivh/Uvh command
newVersionFile="CARKpsmp-13.01.0.4.x86_64.rpm" #update this locally
newLibSSHFile="libssh-0.9.4.x86_64.rpm" #update this locally
newIntergratedInfraFile="CARKpsmp-infra-13.01.0.4.x86_64.rpm" #update this locally

#packagenames (this goes with every -qa command)
newVersion="CARKpsmp-13.01.0-4.x86_64" #UPDATE this to the latest version always (It's usually diff than the .rpm file we define above, it has dash instead of dot.)
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
pvwaGetUser=$(curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/Users?filter=componentUser\&search=$credUsername&UserType=PSMPServer" \
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
			pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
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

createUserCred(){
# Check if file already exists
if [ -f "user.cred" ]; then # file already exists 
	echo -e "***** ${YELLOW}Detected 'user.cred' file already exists, if you created it manually press 'Y' otherwise press 'N' and we will recreate it.${NC}"
	read -r -p  "***** Your response? 'Y' or 'N': " response
	if [[ $response =~ ^([nN][eE][sS]|[nN])$ ]]
		then
		echo "***** Selected 'N', recreating user credential file..."
		./CreateCredFile user.cred Password -Username $adminuser -Password $adminpass -EntropyFile
		# Check if cred file was created
		if [ ! -f "user.cred" ]; then # file was not created
			echo -e "***** ${RED}Couldn't create cred file 'user.cred' from the credentials you've entered, most likely due to permission issue, try doing it manually.${NC}"
			echo -e "***** ${RED}Example Command: ./CreateCredFile user.cred Password -Username <YourInstallUsernameHere> -Password <YourInstallPWHere> -EntropyFile${NC}"
			echo -e "***** ${RED}Exiting...${NC}"
			exit
		fi
	fi
else
	# file doesn't exist, lets create it.
	./CreateCredFile user.cred Password -Username $adminuser -Password $adminpass -EntropyFile
	# Check if cred file was created
	if [ ! -f "user.cred" ]; then # file was not created
		echo -e "***** ${RED}Couldn't create cred file 'user.cred' from the credentials you've entered, most likely due to permission issue, try doing it manually.${NC}"
		echo -e "***** ${RED}Example Command: ./CreateCredFile user.cred Password -Username <YourInstallUsernameHere> -Password <YourInstallPWHere> -EntropyFile${NC}"
		echo -e "***** ${RED}Exiting...${NC}"
		exit
	fi
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
					pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
				else
					pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
				fi
			else
				read -r -p "couldn't grab PVWA URL, please enter it manually (ie; https://mikeb.privilegecloud.cyberark.cloud)." pvwaURL
				extractSubDomainFromURL=${pvwaURL%%.*}
				TrimHTTPs=${extractSubDomainFromURL#*//}
				#Check if URL belongs to UM env, otherwise use legacy.
				if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
					pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
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
					pvwaLogoff
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

disableNSCD(){
nscdname="nscd"
nscdfilepath="/etc/nscd.conf"

echo "**** Checking if $nscdname password chaching needs to be disabled...."
nscdpasswd=`egrep -s "enable-cache[[:blank:]]*passwd[[:blank:]]*yes" $nscdfilepath`
nscdgroup=`egrep -s "enable-cache[[:blank:]]*group[[:blank:]]*yes" $nscdfilepath`

# sed -i 's/  */ /g' $nscdfilepath # reduce multiple spaces to single.

if [[ $nscdpasswd ]] || [[ $nscdgroup ]];
then
	echo -e "**** ${YELLOW}Detected $nscdname password caching (passwd + group) is enabled, will try to disable based on this article:${NC}"
	echo -e "**** ${YELLOW}https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-prerequ-PSM-SSH.htm#DisableNSCD ${NC}"
	# find the string disregarding spaces or tabs.
	egrep "enable-cache[[:blank:]]*passwd[[:blank:]]*yes" $nscdfilepath | xargs -I '{}' sed -i $'s/{}/enable-cache\t\tpasswd\t\tno/g' $nscdfilepath # xargs will replace found string keeping the right format (tabs/spaces).
	egrep "enable-cache[[:blank:]]*group[[:blank:]]*yes" $nscdfilepath | xargs -I '{}' sed -i $'s/{}/enable-cache\t\tgroup\t\tno/g' $nscdfilepath
	echo "**** Restarting $nscdname service..."
	service nscd restart
	service nscd status
	echo "**** Checking $nscdname password caching is now disabled..."
	nscdpasswd=`egrep -s "enable-cache[[:blank:]]*passwd[[:blank:]]*yes" $nscdfilepath`
	nscdgroup=`egrep -s "enable-cache[[:blank:]]*group[[:blank:]]*yes" $nscdfilepath`
		if [[ $nscdpasswd ]] || [[ $nscdgroup ]];
		then
			echo -e "**** ${RED}Failed! guess we couldn't edit the file $nscdfilepath please do it manually.${NC}"
			echo "**** Exiting..."
			exit
		else
			echo -e "**** ${GREEN}Confirmed $nscdname password caching setting is now disabled.${NC}"
		fi
fi
}

maintenanceUsers(){
# Disclaimer for Maintenance Users
sshdfile="/etc/ssh/sshd_config"
psmusers="PSMConnectUsers"
psmpgroup="proxymanagers"
psmpuser="proxymng"

echo -e "**** ${YELLOW} Please note, after install is completed, by default only ${PURPLE}ROOT${YELLOW} account will be able to login.${NC}"
echo -e "**** ${YELLOW} We recommend setting up maintenace accounts that can be used to login with. We also recommend onboarding them to CyberArk.${NC}"
read -r -p "$(echo -e "**** ${YELLOW} Would you like the script attempt to set it up?: [Y/N] ${NC}")" response
if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "**** Chosen YES"
    sleep 1

	# Catch last command exit status, if not 0 then error out.
	checkForError(){
		if [[ $? -ne 0 ]]
		then 
			echo -ne "\r$msg ${RED}FAIL${NC}"
			echo ""
			# proceed to next command anyway
			read -r -p "**** Proceed anyway? [Y/N] " response
			if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
			then
				echo "Proceeding..."
			else
				echo "Exiting..."
				exit
			fi
		else
			echo -ne "\r$msg ${GREEN}PASS${NC}"
			echo ""
		fi
	}
	
	# Create user
	msg="**** Creating user '$psmpuser':"
	echo -ne "$msg" && sleep 2
	adduser $psmpuser
	checkForError
	
	# Create password
	msg="**** Generating strong password for user:"
	echo -ne "$msg" && sleep 2
	#generate random temp pw from 2 methods and combine them to create a strong pw.
	randomPW1=`tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo ''`
	randomPW2=`date | md5sum` && randomPWtrim=`echo $randomPW2 | cut -d' ' -f1`
	randomPW="${randomPW1}${randomPWtrim::-23}" 
	echo $randomPW | passwd --stdin $psmpuser --force > /dev/null 2>&1
	checkForError
	echo -e "**** ${PURPLE} * SAVE THE PASSWORD BEFORE PROCEEDING *:${NC}"
	echo -e "${PURPLE}User:${NC} '$psmpuser'"
	echo -e "${PURPLE}Password:${NC} '${randomPW}'"
	read -p "**** Ready to proceed? Press ENTER"
	
	# Create group
	msg="**** Creating group '$psmpgroup':"
	echo -ne "$msg" && sleep 2
	groupadd $psmpgroup
	checkForError
	
	# Add user to group
	msg="**** Adding new user to new group"
	echo -ne "$msg" && sleep 2
	usermod -a -G $psmpgroup $psmpuser
	checkForError
	
	# Configure sshd_config
	echo -e "**** Let's edit $sshdfile to allow group to connect post hardening." && sleep 2
	# This will find AllowGroups and then in the same line try to find PSMConnectUsers, if true then both were found.
	allowgroupsexist=`egrep -w -E -s "^AllowGroups" $sshdfile | grep "$psmusers"` # '^' will ignore # (hashtags) to avoid commented lines.
	onlyallowgroupsexist=`egrep -w -E -s "^AllowGroups" $sshdfile` # '^' will ignore # (hashtags) to avoid commented lines.
	
	echo "**** Checking if $psmusers were already configured with AllowGroups under $sshdfile..."
	# check if allowgroups and PSMConnectUsers exists in the same line
	if [[ $allowgroupsexist ]]
	then
		echo -e "**** ${GREEN}Group is already defined, nothing to do here.${NC}"
	else
		echo -e "**** Not found, let's backup the file and modify it with our settings.."
		\cp $sshdfile $sshdfile.orig # force overwrite
		if [ ! -f "$sshdfile.orig" ]
		then
			read -r -p "$(echo -e "**** ${RED} Couldn't copy file, proceed anyway? [Y/N] ${NC}")" response
			if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]];then
				echo "**** Proceeding..."
			else
				echo "**** Exiting..."
				exit
			fi
		else
			echo "**** File backup is created: $sshdfile.orig"
		fi
		echo -e "**** Modifying AllowGroup into $sshdfile..." && sleep 2
		# if AllowGroups exist and not PSMConnectUsers group, append just PSMConnectUsers
		if [ ! -z $allowgroupsexist ];
		then
			# Append only PSMConnectUsers & proxymanagers at the end of the line
			egrep -w -E -s "^AllowGroups" $sshdfile | xargs -I '{}' sed -i '/^AllowGroups/ s/$/ '$psmusers' '$psmpgroup'/' $sshdfile
		else
			# Append everything
			echo "AllowGroups $psmusers $psmpgroup" >> $sshdfile
		fi
		echo -e "**** ${GREEN}Done setting up maintenace accounts!${NC}"
		echo -e "**** ${GREEN}Actions Performed:${NC}" && sleep 2
		echo -e "**** ${GREEN}Created User: $psmpuser ${NC}"
		echo -e "**** ${GREEN}Created Group: $psmpgroup ${NC}"
		echo -e "**** ${GREEN}AllowGroups $psmusers $psmpgroup -> Appended to: $sshdfile ${NC}"
	fi
else
	echo "**** Chosen NO, proceeding with install."
	sleep 2
	echo "**** Remember you can always do this manually:"
	echo "https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/PASIMP/Administrating-the-PSMP.htm#Createamaintenanceuser"
	sleep 4
fi
}



if [ "$EUID" -ne 0 ]; then
  read -p "***** Please run as root - Press ENTER to logout..."
  exit
fi

# check we are not running from /tmp/ folder, its notorious for permission issues.
if [[ $PWD = /tmp ]] || [[ $PWD = /tmp/* ]] ; then
	read -p "***** Detected /tmp folder, it is known for problematic permission issues during install, move the install folder to a different path (example /home/) and retry..."
	exit
fi 

# Check psmpparms.sample file exists in script dir, so we know we are in the right place.
if [ ! -f "$LIBCHK" ]; then
  echo "***** can't find file: $LIBCHK are we in the correct installation folder?"
  read -p "***** - Press ENTER to exit..."
  exit 1
fi


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
				################################## NSCD
				disableNSCD
				################################## psmpparms
				editPsmpparms
				################################## cred file
				echo "***** CredFile Creation *****"
				chmod 755 CreateCredFile
				echo " "
				creds # user input creds
				PVWAAUTH # PVWA CHECK
				sleep 8
				createUserCred # create user cred file
				echo ""
				echo ""
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
					################################## NSCD
					disableNSCD
					################################### psmpparms
					editPsmpparms
					################################## cred file
					echo "***** CredFile Creation *****"
					chmod 755 CreateCredFile
					echo " "
					creds # user input creds 
					PVWAAUTH # PVWA CHECK
					sleep 8
					createUserCred # create user cred file
					echo ""
					echo ""
					echo "***** Start repair, this may take some time..."
					rpm -Uvh --force $newVersionFile  &> $psmpwizerrorlog #Repair
						if [[ ! `cat $psmpwizerrorlog | grep error` ]]
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

############## maintenace users
maintenanceUsers

################################### Disable nscd pw caching based on article:
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system-level_authentication_guide/usingnscd-sssd
# https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-prerequ-PSM-SSH.htm#DisableNSCD
disableNSCD
	

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
createUserCred # create user cred file
echo ""
echo ""



################################### rpm installation
echo "***** Primary RPM Installation, This may take some time...*****"
rpm --import RPM-GPG-KEY-CyberArk
echo "***** Installing: $newIntergratedInfraFile"
rpm -ivh ./IntegratedMode/$newIntergratedInfraFile &> $psmpwizerrorlog
	if [[ `rpm -qa | grep CARKpsmp-i` ]] && [[ ! `cat $psmpwizerrorlog | grep error` ]] #package must be installed and no errors in log
	then 
		echo -e "***** ${GREEN}RPM package install successful: $newIntergratedInfraFile${NC}"
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
		echo -e "***** ${GREEN}RPM package install successful: $newVersionFile${NC}"
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


echo -e "***** Some tips:" && sleep 2
echo -e "***** 1. Onboard the maintenace account we've created earlier (if not already). Best practice is to connect to it through the windows PSM component (PSM-SSH Connection Component)." && sleep 2
echo -e "***** 2. Enable MFA Caching: https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/PASIMP/MFA-Caching.htm" && sleep 2
echo -e "***** 3. Usage examples for PSMP: https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-connect-using-SSH.htm#Usageexamples" && sleep 2