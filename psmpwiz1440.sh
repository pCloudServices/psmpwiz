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
PSMPLOGS=psmplogs.chk

VERSION_PSMP="v14.4" # UPDATE THIS (This is just for UI sake, it doesn't impact anything in the script)
scriptVersion="8" # Script version, only dev should update this.

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
minimalFolderSize=150 # This is used to make sure download is not corrupted, the number is just a ballpark number I chose, typically installs are 170mb+
vaultIniTimeout=60

#filenames (because package is different than actual file) - this goes with every -ivh/Uvh command
newVersionFile="CARKpsmp-14.1.2.4.x86_64.rpm"                #update this locally
newIntergratedInfraFile="CARKpsmp-infra-14.1.2.4.x86_64.rpm" #update this locally

#packagenames (this goes with every -qa command)
newVersion="CARKpsmp-14.1.2-4.x86_64"       #UPDATE this to the latest version always (It's usually diff than the .rpm file we define above, it has dash instead of dot.)
newVersionSha256="9e2fbfc0bc750f3d7de99400d89e0b932c6485d2df97e8cba7712c1e1080dfb4" # UPDATE this, example command: sha256sum CARKpsmp-14.1.1.4.x86_64.rpm | awk '{print $1}' 
currVersion=$(rpm -qa | grep CARKpsmp-1)     #this grabs only CARKpsmp because of the "-1" (ie 11.05, 12.01, 12.02) to get accurate single package return
package_to_remove=$(rpm -qa | grep CARKpsmp) #this grabs both CARKpsmp and Infra, to make sure we delete everything.

#PSMP config files
pspmpcredfiles=("/etc/opt/CARKpsmp/vault/psmpappuser.cred" "/etc/opt/CARKpsmp/vault/psmpgwuser.cred")
envmanager="/opt/CARKpsmp/bin/envmanager"

#Check for SUSE
if [[ $(cat /etc/os-release | grep -i suse) ]]; then
    echo "****** Detected SUSE os under: /etc/os-release"
    echo "****** The script unfortunately doesn't support SUSE yet :("
    exit 1
fi

#Functions
#PVWA Calls
pvwaLogin() {
    rest=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w " %{http_code}" "$pvwaURLAPI/Auth/CyberArk/Logon" \
        --header "Content-Type: application/json" \
        --data @<(
            cat <<EOF
{
	"username": "$adminuser",
	"password": "$adminpass",
	"concurrentSession": "false"
}
EOF
        ))
}

pvwaLogoff() {
    pvwaActivate=$(
        curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Auth/Logoff" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaGetUserId() {
    pvwaGetUser=$(
        curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/Users?filter=componentUser\&search=$credUsername&UserType=PSMPServer" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaActivateUser() {
    pvwaActivate=$(
        curl --location -k -m 40 --connect-timeout 5 -s -d "" --request POST --w "%{http_code}" "$pvwaURLAPI/Users/$userID/Activate" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

pvwaResetPW() {
    pvwaReset=$(curl --location -k -m 40 --connect-timeout 5 -s --request POST --w " %{http_code}" "$pvwaURLAPI/Users/$userID/ResetPassword" \
        --header "Content-Type: application/json" \
        --header "Authorization: $pvwaHeaders" \
        --data @<(
            cat <<EOF
{
	"id": "$userID",
	"newPassword": "$randomPW",
	"concurrentSession": "false"
}
EOF
        ))
}

pvwaSystemHealthUser() {
    pvwaSystemHealth=$(
        curl --location -k -m 40 --connect-timeout 5 -s --request GET --w " %{http_code}" "$pvwaURLAPI/ComponentsMonitoringDetails/SessionManagement" \
            --header "Content-Type: application/json" \
            --header "Authorization: $pvwaHeaders"
    )
}

PVWAAUTH() {
    read -r -p "*****(Optional) Would you like to validate the entered credentials? this will require you to input your Privilege Cloud Portal URL & Make sure FW is open on 443 [Y/N] " response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        # if pvwaURL is empty, prompt for pvwa, otherwise use it from previous call.
        if [[ ! $pvwaURL ]]; then
            read -r -p "Please enter your Privilege Cloud Portal URL (eg; https://mikeb.cyberark.cloud): " pvwaURL
        fi
        extractSubDomainFromURL=${pvwaURL%%.*}
        TrimHTTPs=${extractSubDomainFromURL#*//}

        #Check if URL belongs to UM env, otherwise use legacy.
        if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
            pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
        else
            pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
        fi
        echo "Making API call to: " $pvwaURLAPI
        echo "Will timeout in 20s if doesn't reach Portal on 443..."
        #call login
        pvwaLogin
        if [[ $(echo $rest | grep "200") ]]; then
            echo -e "${GREEN}Validation Passed!${NC}"
        else
            read -r -p "***** Validation Failed, do you want to continue anyway? [Y/N] " response
            if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
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

creds() {
    read -p "Please Enter Privilege Cloud Install Username: " adminuser
    echo " "
    echo "***** Please Enter Privilege Cloud Install User Password and press ENTER *****"
    read -s adminpass
    if [ -z "$adminpass" ]; then
        echo "password is empty, rerun script"
        exit 1
    else
        adminpw="$(echo -e "${adminpass}" | tr -d '[:space:]')"
    fi
}

createUserCred() {
    # Check if file already exists
    if [ -f "user.cred" ]; then # file already exists
        echo -e "***** ${YELLOW}Detected 'user.cred' file already exists, if you created it manually press 'Y' otherwise press 'N' and we will recreate it.${NC}"
        read -r -p "***** Your response? 'Y' or 'N': " response
        if [[ $response =~ ^([nN][eE][sS]|[nN])$ ]]; then
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

editPsmpparms() {
    \cp psmpparms.sample $psmpparms
    echo "***** Updating the psmpparms file *****"
    sed -i 's|AcceptCyberArkEULA=No|AcceptCyberArkEULA=Yes|g' $psmpparms
    awk '{sub(/InstallationFolder=<Folder Path>/,"InstallationFolder='"$PWD"/'")}1' $psmpparms >$psmpparmstmp && mv $psmpparmstmp $psmpparms && rm -rf $psmpparmstmp
    sed -i 's|InstallCyberArkSSHD=Yes|InstallCyberArkSSHD=Integrated|g' $psmpparms
    sed -i 's|#EnableADBridge=Yes|EnableADBridge=No|g' $psmpparms
}

errorLogsPrint() {
    echo -e "*****${RED} Error: Failed to install RPM. Fix the errors and rerun wizard again.${NC}"
    installlogs=("$PWD"/"$psmpwizerrorlog" "$PWD/psmp_install.log" "$PWD/EnvManager.log" "$PWD/EnvManager_Uninstall.log")

    #copy logs to centralized dir
    \cp /var/tmp/psmp_install.log psmp_install.log
    \cp /var/opt/CARKpsmp/temp/EnvManager.log EnvManager.log
	\cp /tmp/temp/EnvManager.log EnvManager_Uninstall.log

    printonce="1"
    for n in ${installlogs[@]}; do
        if [ -s $n ]; then #check file not empty
            #make sure to print this line only once for the whole loop.
            if [[ $printonce -eq 1 ]]; then
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

resetCredFile() {
    #files
    pspmpcredfiles=("/etc/opt/CARKpsmp/vault/psmpappuser.cred" "/etc/opt/CARKpsmp/vault/psmpgwuser.cred")
    pvconfigurationFile="/var/opt/CARKpsmp/temp/PVConfiguration.xml"
    createcredfile="/opt/CARKpsmp/bin/createcredfile"
    clear
    echo "***** To perform this task we must be able to reach your cloud portal (ie; https://mikeb.privilegecloud.cyberark.cloud) via HTTPS/443."
    echo ""
    read -r -p "***** Do you want to continue? [Y/N] " response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "***** Selected YES..."
        #grab pvwa url
        echo "***** Grabbing PVWA URL from: $pvconfigurationFile"
        if [ -s $pvconfigurationFile ]; then
            pvwaURL=$(cat $pvconfigurationFile | grep -oP '(?<=ApplicationRoot=").*?(?=")')
            echo -e "***** PVWA URL is: ${GREEN}$pvwaURL${NC}"
            extractSubDomainFromURL=${pvwaURL%%.*}
            TrimHTTPs=${extractSubDomainFromURL#*//}
            if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
                pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.cloud/passwordvault/api
            else
                pvwaURLAPI=https://$TrimHTTPs.privilegecloud.cyberark.com/passwordvault/api
            fi
        else
            read -r -p "couldn't grab PVWA URL, please enter it manually (ie; https://mikeb.privilegecloud.cyberark.cloud):" pvwaURL
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
        creds     # get user input
        pvwaLogin #call login
        if [[ $(echo $rest | grep "200") ]]; then
            echo -e "*****${GREEN} Connected!${NC}"
            # grab headers
            pvwaHeaders=$(echo $rest | cut -d' ' -f1 | tr -d '"')
        else
            echo -e "***** ${RED}Connection failed...${NC}"
            echo $rest
            echo -e "***** ${RED}Unable to proceed, fix connection to PVWA and rerun the script.${NC}"
            exit 1
        fi

        for n in ${pspmpcredfiles[@]}; do #both app and gw
            echo "***** Generating CredFile: $n"
            if [ -s $n ]; then #check file not empty
                credUsername=$(cat $n | grep -oP '(?<=Username=).*(?=)')
                echo -e "***** Grabbed username: ${PURPLE}$credUsername${NC}"
                #generate random temp pw from 2 methods and combine them to create a strong pw.
                randomPW1=$(
                    tr -dc A-Za-z0-9 </dev/urandom | head -c 13
                    echo ''
                )
                randomPW2=$(date | md5sum) && randomPWtrim=$(echo $randomPW2 | cut -d' ' -f1)
                randomPW="${randomPW1}${randomPWtrim::-27}" #-27 to avoid the 39 char limit and repeating chars.
                $createcredfile $n Password -Username "$credUsername" -Password "$randomPW" -EntropyFile
                #get user ID
                echo "***** Retrieving UserID for user $credUsername"
                pvwaGetUserId
                userID=$(echo $pvwaGetUser | grep -oP '(?<="id":).*?(?=,)') # grabs user id
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
                if [[ $(echo $pvwaReset | grep "200") ]]; then
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
        appName=$(echo $credUsername | cut -d'_' -f2) #better to search the exact name instead of with app/gw prefix.
        status=$(echo $pvwaSystemHealth | grep -oP "($appName).*?(?="LastLogonDate")" | grep -oP '(?<="IsLoggedOn":).*?(?=,)')
        if [[ $(echo $status | grep "true") ]]; then
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

disableNSCD() {
    nscdname="nscd"
    nscdfilepath="/etc/nscd.conf"

    msg="**** Checking If $nscdname password caching needs to be disabled..."
    echo -ne "$msg" && sleep 2 
    nscdpasswd=$(egrep -s "enable-cache[[:blank:]]*passwd[[:blank:]]*yes" $nscdfilepath)
    nscdgroup=$(egrep -s "enable-cache[[:blank:]]*group[[:blank:]]*yes" $nscdfilepath)

    # sed -i 's/  */ /g' $nscdfilepath # reduce multiple spaces to single.

    if [[ $nscdpasswd ]] || [[ $nscdgroup ]]; then
        echo -e "**** ${YELLOW}Detected $nscdname password caching (passwd + group) is enabled, will try to disable based on this article:${NC}"
        echo -e "**** ${YELLOW}https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-prerequ-PSM-SSH.htm#DisableNSCD ${NC}"
        # find the string disregarding spaces or tabs.
        egrep "enable-cache[[:blank:]]*passwd[[:blank:]]*yes" $nscdfilepath | xargs -I '{}' sed -i $'s/{}/enable-cache\t\tpasswd\t\tno/g' $nscdfilepath # xargs will replace found string keeping the right format (tabs/spaces).
        egrep "enable-cache[[:blank:]]*group[[:blank:]]*yes" $nscdfilepath | xargs -I '{}' sed -i $'s/{}/enable-cache\t\tgroup\t\tno/g' $nscdfilepath
        echo "**** Restarting $nscdname service..."
        service nscd restart
        service nscd status
        echo "**** Checking $nscdname password caching is now disabled..."
        nscdpasswd=$(egrep -s "enable-cache[[:blank:]]*passwd[[:blank:]]*yes" $nscdfilepath)
        nscdgroup=$(egrep -s "enable-cache[[:blank:]]*group[[:blank:]]*yes" $nscdfilepath)
        if [[ $nscdpasswd ]] || [[ $nscdgroup ]]; then
            echo -e "**** ${RED}Failed! guess we couldn't edit the file $nscdfilepath please do it manually.${NC}"
            echo "**** Exiting..."
            exit
        else
            echo -e "**** ${GREEN}Confirmed $nscdname password caching setting is now disabled.${NC}"
        fi
	else
        echo -e "\r$msg ${GREEN}PASS${NC}"
    fi
}

maintenanceUsers() {
    # Disclaimer for Maintenance Users
    sshdfile="/etc/ssh/sshd_config"
    psmusers="PSMConnectUsers"
    psmpgroup="proxymanagers"
    psmpuser="proxymng"

    echo -e "**** ${YELLOW} Please note, after install is completed, machine is hardened and ${PURPLE}ROOT${YELLOW} account will only be able to login through console, not via SSH.${NC}"
    echo -e "**** ${YELLOW} We recommend setting up maintenance accounts that can be used to login with via SSH. We also recommend onboarding them to CyberArk.${NC}"
    read -r -p "$(echo -e "**** ${YELLOW} Would you like the script attempt to set it up?: [Y/N] [Recommended: Yes]: ${NC}")" response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "**** Chosen YES"
        sleep 1
    else
        echo "**** Chosen NO, proceeding with install."
        sleep 1
        echo "**** Remember you can always do this manually:"
        echo "https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/PASIMP/Administrating"
        sleep 1
		return
    fi
    checkForError() {
        if [[ $? -ne 0 ]]; then
            echo -ne "\r$msg ${RED}FAIL${NC}"
            echo ""
            read -r -p "**** Proceed anyway? [Y/N]: " response
            if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
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

    checkSudoUsage() {
        local count=0

        echo "**** Checking if sudo is in use..."

        # Check 1: Audit Log Files
        if grep -q sudo /var/log/auth.log 2>/dev/null || grep -q sudo /var/log/secure 2>/dev/null; then
            ((count++))
        fi

        # Check 2: sudoers Configuration
        if [ -s /etc/sudoers ]; then
            ((count++))
        fi

        # Check 3: List Users in sudoers Group
        if getent group sudo &>/dev/null || getent group wheel &>/dev/null; then
            ((count++))
        fi

        # Check 4: Custom sudoers Directories
        if [ -d /etc/sudoers.d/ ] && [ "$(ls -A /etc/sudoers.d/)" ]; then
            ((count++))
        fi

        # Check 5: Check the Environment for SUDO_COMMAND
        if [ -n "$SUDO_COMMAND" ]; then
            ((count++))
        fi

        # If 3 or more checks pass
        if [ "$count" -ge 3 ]; then
            echo -e "**** ${YELLOW}determined sudo is enabled and utilized on this environment.${NC}"
            return 0
        else
            return 1
        fi
    }
    checkGroupInSudoers() {
        local group_name="$1"
        if grep -qE "^%$group_name" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
            return 0
        else
            return 1
        fi
    }

    # Create user
    msg="**** Creating user '$psmpuser'..."
    echo -ne "$msg" && sleep 2
    adduser $psmpuser
    checkForError

    # Create password
    msg="**** Generating strong password for user..."
    echo -ne "$msg" && sleep 2
    #generate random temp pw from 2 methods and combine them to create a strong pw.
    randomPW1=$(
        tr -dc A-Za-z0-9 </dev/urandom | head -c 13
        echo ''
    )
    randomPW2=$(date | md5sum) && randomPWtrim=$(echo $randomPW2 | cut -d' ' -f1)
    randomPW="${randomPW1}${randomPWtrim::-23}"
    echo $randomPW | passwd --stdin $psmpuser --force >/dev/null 2>&1
    checkForError
    echo -e "${PURPLE}User:${NC} '$psmpuser'"
	echo -e "**** ${YELLOW} You are about to see $psmpuser password, please don't show it to others and hide your screen before proceeding. ${NC}"
	read -p "**** Press ENTER when ready."
    echo -e "${PURPLE}Password:${NC} '${randomPW}'"
	echo -e "**** ${PURPLE} * SAVE THE PASSWORD BEFORE PROCEEDING *:${NC}"
    read -p "**** Ready to proceed? Press ENTER"
	clear

    # Create group
    msg="**** Creating group '$psmpgroup'..."
    echo -ne "$msg" && sleep 2
    groupadd $psmpgroup
    checkForError

    # Add user to group
    msg="**** Adding new user to new group..."
    echo -ne "$msg" && sleep 2
    usermod -a -G $psmpgroup $psmpuser
    checkForError

    # Configure sshd_config
    echo -e "**** Let's edit $sshdfile to allow group to connect post hardening." && sleep 2
    # This will find AllowGroups and then in the same line try to find PSMConnectUsers, if true then both were found.
    allowgroupsexist=$(egrep -w -E -s "^AllowGroups" $sshdfile | grep "$psmusers") # '^' will ignore # (hashtags) to avoid commented lines.
    onlyallowgroupsexist=$(egrep -w -E -s "^AllowGroups" $sshdfile)                # '^' will ignore # (hashtags) to avoid commented lines.

    echo "**** Checking if $psmusers were already configured with AllowGroups under $sshdfile..."
    # check if allowgroups and PSMConnectUsers exists in the same line
    if [[ $allowgroupsexist ]]; then
        echo -e "**** ${GREEN}Group is already defined, nothing to do here.${NC}"
    else
        echo -e "**** Not found, let's backup the file and modify it with our settings.."
        \cp $sshdfile $sshdfile.orig # force overwrite
        if [ ! -f "$sshdfile.orig" ]; then
            read -r -p "$(echo -e "**** ${RED} Couldn't copy file, proceed anyway? [Y/N]: ${NC}")" response
            if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
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
        if [ ! -z $allowgroupsexist ]; then
            # Append only PSMConnectUsers & proxymanagers at the end of the line
            egrep -w -E -s "^AllowGroups" $sshdfile | xargs -I '{}' sed -i '/^AllowGroups/ s/$/ '$psmusers' '$psmpgroup'/' $sshdfile
        else
            # Append everything
            echo "AllowGroups $psmusers $psmpgroup" >>$sshdfile
        fi
    fi

        # Check if sudo is actively used and offer to add user to sudoers
        if checkSudoUsage; then
			read -r -p "**** Would you like to configure $psmpuser for sudo use? [Y/N] [Recommended: Yes]: " sudo_config_response
			if [[ $sudo_config_response =~ ^([yY][eE][sS]|[yY])$ ]]; then
				echo "**** Checking if wheel or sudo groups are part of sudoers..."
				local sudo_group=""
				local sudo_exists=false
				local wheel_exists=false
	
				if getent group sudo &>/dev/null && checkGroupInSudoers sudo; then
					sudo_exists=true
				fi
				if getent group wheel &>/dev/null && checkGroupInSudoers wheel; then
					wheel_exists=true
				fi
	
				if $sudo_exists && $wheel_exists; then
					echo "Both sudo and wheel groups are available for sudo privileges."
					read -r -p "**** Which group would you like to add $psmpuser to (sudo/wheel) ? " sudo_group
					if [[ ! $sudo_group =~ ^(sudo|wheel)$ ]]; then
						echo "Invalid group. Exiting..."
						return
					fi
				elif $sudo_exists; then
					sudo_group="sudo"
					echo "**** sudo group '$sudo_group' exists in sudoers list."
				elif $wheel_exists; then
					sudo_group="wheel"
					echo "**** sudo group '$sudo_group' exists in sudoers list."
				else
					echo "**** Neither 'sudo' nor 'wheel' group is configured for sudo privileges."
					read -r -p "**** Please specify a custom group to add $psmpuser to: " custom_group
					if getent group "$custom_group" &>/dev/null; then
						sudo_group="$custom_group"
					else
						echo "**** Group '$custom_group' does not exist. Exiting..."
						return
					fi
				fi
	
				read -r -p "**** Would you like to add '$psmpuser' to the '$sudo_group' group for sudo privileges? [Y/N] [Recommended: Yes]: " response
				if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
					msg="**** Adding $psmpuser to $sudo_group group..."
					echo -ne "$msg" && sleep 2
					usermod -a -G $sudo_group $psmpuser
					checkForError
					sudoComplete=`echo -e "**** ${GREEN}Added $psmpuser to sudo group: $sudo_group ${NC}"`
				fi
			else
				echo "**** Skipping sudo configuration for $psmpuser."
			fi	
        else
            echo "**** sudo does not seem to be actively used on this system."
        fi
            echo -e "**** ${GREEN}Done setting up maintenance accounts!${NC}"
            echo -e "**** ${GREEN}Actions Performed:${NC}" && sleep 2
            echo -e "**** ${GREEN}Created User: $psmpuser ${NC}"
            echo -e "**** ${GREEN}Created Group: $psmpgroup ${NC}"
            echo -e "**** ${GREEN}AllowGroups $psmusers $psmpgroup -> Appended to: $sshdfile ${NC}"
			echo "$sudoComplete"
}

checkFolderSize() {
    msg="**** Checking Installation folder size..."
    echo -ne "$msg" && sleep 2
    current_size=$(du -s . | awk '{print $1}') # Get current folder size in KB

    current_size_MB=$(($current_size / 1024)) # Convert size to MB

    if [ $current_size_MB -lt $minimalFolderSize ]; then
        echo -e "\r$msg ${RED}FAIL${NC}" # Update the dynamic part while preserving the original message context.
        echo -e "${YELLOW}The installation folder seems to be too small (${current_size_MB}MB), please make sure it was downloaded and extracted correctly.${NC}"
        read -r -p "Do you want to continue? Type Yes/No: " response
        if [[ ! $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "***** - Press ENTER to exit..."
            exit 1
        fi
    else
        echo -e "\r$msg ${GREEN}PASS${NC}"
    fi
}


checkMinimumFreeDiskSpace() {
    msg="**** Checking Minimal disk space..."
    echo -ne "$msg" && sleep 2
    free_space_kb=$(df . | awk 'NR==2 {print $4}')
	
	# Convert to MB
    free_space_mb=$((free_space_kb / 1024))
	
	# Set minimum required space in MB (1GB)
    min_space_mb=1024
    
    if [ $free_space_mb -lt $min_space_mb ]; then
        echo -e "\r$msg ${YELLOW}FAIL${NC}" # Update the dynamic part while preserving the original message context.
        echo -e "${YELLOW}Not enough free space: ${free_space_mb}MB available, but 1GB is required to run the installation.${NC}"
        echo -e "${YELLOW}You should know that official docs require 80GB of free space.${NC}"
        echo "***** - Press ENTER to exit..."
        read
        exit 1
    else
        echo -e "\r$msg ${GREEN}PASS${NC}"
    fi
}


# Check supported OS
perform_os_checks() {
    msg="**** Checking Supported OS..."
    echo -ne "$msg" && sleep 2

    # check valid range
    is_version_valid() {
        local version=$1
        local min_version=$2
        local max_version=$3

        if [[ $(echo -e "$min_version\n$version" | sort -V | head -n1) == "$min_version" ]] && \
           [[ $(echo -e "$max_version\n$version" | sort -V | head -n1) == "$version" ]]; then
            return 0 # True, version is within range
        else
            return 1 # False, version is out of range
        fi
    }

    # Decision
    prompt_user_decision() {
        read -r -p "The operating system ($PRETTY_NAME) is not officially supported. Do you want to continue? Type Yes/No: " response
        if [[ ! $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "Installation aborted. Press ENTER to exit..."
            read -p "***** - Press ENTER to exit..."
            exit 1
        fi
    }

    # Get OS info
    source /etc/os-release

    # Check each distribution and version
    case $ID in
        "rhel")
            if is_version_valid $VERSION_ID 7 7.9 || \
               [[ $VERSION_ID == 8.* ]] || \
               [[ $VERSION_ID == 9.* ]]; then
                echo -e "\r$msg ${GREEN}PASS${NC}"
            else
                echo -e "${RED}Unsupported version: $PRETTY_NAME. Supported versions are Red Hat Enterprise Linux versions 7 up to 7.9, 8 up to 8.9, and 9.x.${NC}"
                prompt_user_decision
            fi
            ;;
        "centos")
            # Centos requires different approach to check OS
            local centos_version=$(grep -oP '(?<=release )\d+(\.\d+)?' /etc/centos-release)
            if [[ $centos_version == "7.9" ]]; then
                echo -e "\r$msg ${GREEN}PASS${NC}"
            else
                echo -e "${RED}Unsupported version: CentOS $centos_version. Supported version is CentOS Linux 7.9.${NC}"
                prompt_user_decision
            fi
            ;;
        "rocky")
			if [[ $VERSION_ID == 8.* ]]; then
                echo -e "\r$msg ${GREEN}PASS${NC}"
            else
                echo -e "${RED}Unsupported version: $PRETTY_NAME. Supported versions are Rocky Linux 8.7, 8.8, 8.9.${NC}"
                prompt_user_decision
            fi
            ;;
        *)
            echo -e "${RED}Unsupported Linux distribution ($PRETTY_NAME).${NC}"
            prompt_user_decision
            ;;
    esac
}


check_puppet_and_proceed() {
	msg="**** Checking For Puppet..."
    echo -ne "$msg" && sleep 2
	
    # List of files to be excluded from being controlled by Puppet
    local files_to_exclude=(
        "/etc/passwd"
        "/etc/sudoers"
        "/etc/yum.conf"
        "/etc/ssh/sshd_config"
        "/etc/pam.d/sshd"
        "/etc/pam.d/password-auth"
        "/etc/nsswitch.conf"
        "/usr/sbin/sshd"
        "/etc/sysconfig/sshd"
    )

    # Check if the puppet service is active
    if systemctl is-active --quiet puppet; then
        echo -e "${YELLOW}Detected Puppet service, it is known to interfere with PSMP Functionality.${NC}"
		echo -e "${YELLOW}Documentation about this: https://docs.cyberark.com/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-prerequ-PSM-SSH.htm#Checkprerequisites ${NC}"
        echo -e "${YELLOW}You should either disable it or exclude the following files from being controlled by Puppet:${NC}"
        for file in "${files_to_exclude[@]}"; do
            echo "- $file"
        done
        
        # Decision
        read -r -p "Do you still want to proceed? [Y/N] [Recommended: No]: " response
        if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "Proceeding with installation..."
        else
            echo "Installation aborted. Exiting..."
            read -p "***** - Press ENTER to exit..."
            exit 1
        fi
	else
		echo -e "\r$msg ${GREEN}PASS${NC}"
    fi
}

check_version_type() {
    msg="**** Checking downloaded CARKpsmp type (Sha256 checksum)..."
    echo -ne "$msg" && sleep 2
    
    expectedSHA256=$newVersionSha256
    currentSHA256=$(sha256sum $newVersionFile | awk '{print $1}')
    
    if [ "$expectedSHA256" != "$currentSHA256" ]; then
        echo -e "\r$msg ${RED}FAIL${NC}"
        echo -e "${RED}Failed to match RPM file '$newVersionFile' with expected checksum. Are you sure you copied the correct zip file? (Note: CyberArk provides two zips: RHELinux, RHELinux8; we want RHELinux8)${NC}"
        read -r -p "Do you still want to proceed? [Y/N] [Recommended: No]: " response
        if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "Proceeding with installation..."
        else
            echo "Installation aborted. Exiting..."
            read -p "***** - Press ENTER to exit..."
            exit 1
        fi
    else
        echo -e "\r$msg ${GREEN}PASS${NC}"
    fi
}

check_hostname() {
	msg="**** Checking hostname is not default..."
	echo -ne "$msg" && sleep 2
	
    current_hostname=$(hostname -s)
    if [[ $current_hostname == "localhost" ]]; then
		echo -e "\r$msg ${RED}FAIL${NC}"
        echo -e "${RED}WARNING: Machine hostname is set to 'localhost'.${NC}"
        echo -e "${YELLOW}This will cause issues if you are installing multiple PSMPs as the service users${NC}"
        echo -e "${YELLOW}that will be created will have duplicate names and fail the installation.${NC}"
        echo ""
        read -r -p "Would you like to proceed anyway? [Y/N]: " response
        if [[ ! $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "Exiting script. Please update the hostname and try again."
            exit 1
        fi
    else
        echo -e "\r$msg ${GREEN}PASS${NC}"
    fi
}

# handle RHEL 9+ versions
configure_rhel9() {
    if [[ $ID == "rhel" && $VERSION_ID == 9* ]]; then
        echo "Detected RHEL 9.x, applying SSH configuration changes..."
        rm -f /etc/ssh/sshd_config.d/20-CARKpsmp.conf
        cat <<EOT >> /etc/ssh/sshd_config.d/20-CARKpsmp.conf
# Added to allow for PSMP to function with RHEL9 DO NOT MODIFY
ChallengeResponseAuthentication yes
usePAM yes

# PSMP Enable debugging by uncommenting the following item
# LogLevel DEBUG3

# PSMP Enable tunneling by uncommenting both items
# AllowTcpForwarding local
# DisableForwarding no

# PSMP Enable sftp by uncommenting the following item
# Subsystem      sftp   /usr/libexec/openssh/sftp-server
EOT
        service sshd restart
        echo "SSH configuration for RHEL 9.x applied and sshd service restarted."
    fi
}



if [ "$EUID" -ne 0 ]; then
    read -p "***** Please run as root - Press ENTER to exit..."
    exit 1
fi

# check we are not running from /tmp/ folder, its notorious for permission issues.
if [[ $PWD = /tmp ]] || [[ $PWD = /tmp/* ]]; then
    read -p "***** Detected /tmp folder, it is known for problematic permission issues during install, move the install folder to a different path (example /home/) and retry..."
	read -p "***** - Press ENTER to exit..."
    exit 1
fi

# Check psmpparms.sample file exists in script dir, so we know we are in the right place.
if [ ! -f "$LIBCHK" ]; then
    echo "***** can't find file: $LIBCHK are we in the correct installation folder?"
    read -p "***** - Press ENTER to exit..."
    exit 1
fi

echo "--------------------------------------------------------------"
echo -e "----------- CyberArk PSMP Installation Wizard ${GREEN}($VERSION_PSMP)${NC} --------"
echo "----------- psmpwiz script version "$scriptVersion" -------------------------"
echo "--------------------------------------------------------------"

########################################################################################
#------------------------------------Check Previous PSMP------------------------------ #
########################################################################################
#check if previous version is installed and only then compare with new version and suggest upgrade
if [ -z "$currVersion" ]; then
    echo "No previous version installed, proceeding with fresh install"
else
    if [[ $newVersion > $currVersion ]]; then
        echo "old $currVersion"
        echo "new $newVersion"
        read -r -p "***** Found an older version, would you like to upgrade? [Y/N] " response
        if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
            ################################## NSCD
            disableNSCD
            ################################## psmpparms
            editPsmpparms
            ################################## cred file
            echo "***** CredFile Creation *****"
            chmod 755 CreateCredFile
            echo " "
            creds    # user input creds
            PVWAAUTH # PVWA CHECK
            sleep 8
            createUserCred # create user cred file
            echo ""
            echo ""
            #Upgrade command
            rpm --import RPM-GPG-KEY-CyberArk
            rpm -Uvh ./IntegratedMode/$newIntergratedInfraFile &>$psmpwizerrorlog
            #check if package is installed and if log file contains error.
            if [[ $(rpm -qa | grep CARKpsmp-i) ]] && [[ ! $(cat $psmpwizerrorlog | grep error) ]]; then
                echo -e "${GREEN}RPM package install successful: $newIntergratedInfraFile${NC}"
            else
                errorLogsPrint
                echo "***** Clearing Credentials *****"
                rm -rf user.cred
                exit 1
            fi
            sleep 2
            echo ""
            rpm -Uvh $newVersionFile &>$psmpwizerrorlog
            if [[ $(rpm -qa | grep CARKpsmp-1) ]] && [[ ! $(cat $psmpwizerrorlog | grep error) ]]; then
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
            if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
                read -r -p "***** Type 'R' to Repair ||| 'U' to Uninstall ||| 'C' to ResetCred " response
                if [[ $response =~ ^([rR|[rR])$ ]]; then
                    ################################## NSCD
                    disableNSCD
                    ################################### psmpparms
                    editPsmpparms
                    ################################## cred file
                    echo "***** CredFile Creation *****"
                    chmod 755 CreateCredFile
                    echo " "
                    creds    # user input creds
                    PVWAAUTH # PVWA CHECK
                    sleep 8
                    createUserCred # create user cred file
                    echo ""
                    echo ""
                    echo "***** Start repair, this may take some time..."
                    rpm -Uvh --force $newVersionFile &>$psmpwizerrorlog #Repair
                    if [[ ! $(cat $psmpwizerrorlog | grep error) ]]; then
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
                if [[ $response =~ ^([uU|[uU])$ ]]; then
					chmod 755 CreateCredFile
                    echo " "
                    creds    # user input creds
                    PVWAAUTH # PVWA CHECK
                    sleep 5
                    createUserCred # create user cred file
				
					# uninstall RPM
                    rpm -e $package_to_remove
                    sleep 1
					
					echo "**** Removing backend configuration"
					psmpapp=$(cat /etc/opt/CARKpsmp/vault/psmpappuser.cred | grep -oP '(?<=Username=).*(?=)')
					psmpgw=$(cat /etc/opt/CARKpsmp/vault/psmpgwuser.cred | grep -oP '(?<=Username=).*(?=)')
					/opt/CARKpsmp/bin/envmanager "TeardownEnv" --AcceptEULA "Y" -CredFile ./user.cred -PSMPAppUser "$psmpapp" -PSMPGWUser "$psmpgw" --VaultEnvPath /etc/opt/CARKpsmp/vault/ &>$psmpwizerrorlog # Delete from backend
					if [[ ! $(cat $psmpwizerrorlog | grep error) ]]; then
						echo -e "${GREEN}Removed successfully.${NC}"
						echo -e "${GREEN}Uninstall is complete.${NC}"
                    else
                        errorLogsPrint
                        echo "***** Clearing Credentials *****"
                        rm -rf user.cred
                        exit 1
                    fi
					
                    exit 1
                fi
                if [[ $response =~ ^([cC|[cC])$ ]]; then
                    resetCredFile
                fi
            else
                exit
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

# Check folder size
checkFolderSize

# Check minimum disk space
checkMinimumFreeDiskSpace

# Check minimum required OS
perform_os_checks

# Apply configuration for RHEL 9+ versions
configure_rhel9

# Check puppet is not running
check_puppet_and_proceed

# Check download version
check_version_type

# Check hostname not default
check_hostname

########################################################################################
#---------------------------------------------- PSMP Installation Wizard---------------#
########################################################################################

################################### Disable nscd pw caching based on article:
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system-level_authentication_guide/usingnscd-sssd
# https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-prerequ-PSM-SSH.htm#DisableNSCD
disableNSCD

############## maintenance users
maintenanceUsers


    ################################### VaultIP
    echo ""
    if [[ ! $pvwaURL ]]; then
        read -r -p "Please enter your Privilege Cloud Portal URL (eg; https://mikeb.cyberark.cloud): " pvwaURL
    fi
    extractSubDomainFromURL=${pvwaURL%%.*}
    TrimHTTPs=${extractSubDomainFromURL#*//}
    #Check if URL belongs to UM env, otherwise use legacy.
    if [[ $pvwaURL == *"cyberark.cloud"* ]]; then
        vaultip=vault-$TrimHTTPs.privilegecloud.cyberark.cloud
    else
        vaultip=vault-$TrimHTTPs.privilegecloud.cyberark.com
    fi

    echo "---------------------------------"
    echo "***** Vault Configuration *****"
    echo -e "***** ${GREEN}Vault Address:${NC} $vaultip "
    read -r -p "***** Please confirm: [Y/N] " response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "***** Done..."
    else
        echo "Chosen NO, offering to input manually.."
        read -p "Enter Vault Address: " vaultip
    fi

    ################################### Connectivity test
    #save connection output to file
    rm -rf /tmp/capture.out
    cap() { tee /tmp/capture.out; }

    echo "***** Connectivity test *****"
    echo ""
    read -r -p "***** Do you want to perform connectivity test to: $vaultip [Y/N] " response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "***** Waiting for Vault response..."
        timeout 3 bash -c '</dev/tcp/'$vaultip'/1858' && echo port is open | cap || echo port is closed | cap
        ret=$(cat /tmp/capture.out) #get result from connection test
        #clear
        if [[ "echo $ret" == *"open"* ]]; then
            echo -e "***** Vault Connectivity test - ${GREEN}*** PASSED ***${NC}"
			if [ ! -f "$VLTFILE" ]; then
			################################### Vault.ini
				sed -i "s/1.1.1.1/"$vaultip"/g" vault.ini
				sed -i "s/TIMEOUT=10/TIMEOUT="$vaultIniTimeout"/g" vault.ini
				echo "vault.ini updated" >stvlt.chk
			fi
			# Check if pvwaURL is a cyberark.cloud and test identity.
			if [[ $pvwaURL == *".cyberark.cloud"* ]]; then
				echo -e "*****${YELLOW} Shared Services platform detected, trying to extract Identity URL from the headers response of '$pvwaURL'.${NC}"
				# Extract 'Location' URL from the tenant URL
				location_url=$(curl -Is "$pvwaURL" | grep -i Location: | awk '{print $2}' | tr -d '\r' | cut -d'/' -f1,2,3)			
				# Check if location_url was successfully extracted
				if [[ -z $location_url ]]; then
					echo -e "*****${RED} Failed to automatically extract Identity URL.${NC}"
					echo -e "***** Please enter the URL manually. (eg; aax4550.id.cyberark.cloud)"
					read -r -p "Enter Location URL: " location_url
				fi			
				if [[ -n $location_url ]]; then
					echo "Extracted Location URL for Identity Connection test: '$location_url'"
					read -r -p "***** Do you want to perform Identity connectivity test? [Y/N] " response
					if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
						echo "***** Testing connectivity to: $location_url"
						# Test connection 
						if curl --output /dev/null --silent --head --fail --connect-timeout 7 "$location_url"; then
							echo -e "***** Connectivity to $location_url - ${GREEN}*** PASSED ***${NC}"
						else
							echo -e "***** Connectivity to $location_url - ${RED}*** FAILED ***${NC}"
							echo "***** Recommendation: Check your network configuration and re-run the installation script"
							read -r -p "***** Do you want to continue anyway? [Y/N] " response
							if [[ ! $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
								echo "***** Please check your network configuration and re-run the installation script."
								exit 1
							fi
						fi
					else
						echo "Identity Connectivity test - skipped"
					fi
				else
					echo -e "*****${RED} No Location URL provided. Unable to perform connectivity test.${NC}"
				fi
			fi
        else
            echo -e "***** Connectivity test - ${RED}*** FAILED ***${NC}"
            echo "***** Recommendation: check your network configuration and re-run the installation script"
            read -r -p "***** Do you want to continue anyway? to: $vaultip [Y/N] " response
            if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
                echo "Connectivity test - skipped"
            else
                echo "***** Please check your network configuration and re-run the installation script"
                exit 1
            fi
        fi
    else
        echo "Connectivity test - skipped"
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
creds    # user input creds
PVWAAUTH # PVWA CHECK
sleep 8
createUserCred # create user cred file
echo ""
echo ""

################################### rpm installation
echo "***** Primary RPM Installation, This may take some time...*****"
rpm --import RPM-GPG-KEY-CyberArk
echo "***** Installing: $newIntergratedInfraFile"
rpm -ivh ./IntegratedMode/$newIntergratedInfraFile &>$psmpwizerrorlog
if [[ $(rpm -qa | grep CARKpsmp-i) ]] && [[ ! $(cat $psmpwizerrorlog | grep error) ]]; then #package must be installed and no errors in log
    echo -e "***** ${GREEN}RPM package install successful: $newIntergratedInfraFile${NC}"
else
    errorLogsPrint
    echo ""
    echo "***** Let's uninstall RPM packages since installation was not completed. *****"
    del=$(rpm -qa | grep CARKpsmp) && rpm -e $del --quiet
    echo "***** Clearing Credentials *****"
    rm -rf user.cred
    exit 1
fi
echo ""
sleep 2
echo "***** Installing: $newVersionFile"
rpm -ivh $newVersionFile &>$psmpwizerrorlog
if [[ $(rpm -qa | grep CARKpsmp-1) ]] && [[ ! $(cat $psmpwizerrorlog | grep error) ]]; then
    echo -e "***** ${GREEN}RPM package install successful: $newVersionFile${NC}"
else
    errorLogsPrint
    echo ""
    echo "***** Let's uninstall RPM packages since installation was not completed. *****"
    del=$(rpm -qa | grep CARKpsmp) && rpm -e $del --quiet
    echo "***** Clearing Credentials *****"
    rm -rf user.cred
    exit 1
fi

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
    cat <<'EOF' >/var/opt/CARKpsmp/logs/archive/logCleaner.sh
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
    crontab -l | {
        cat
        echo "0 4 * * * /var/opt/CARKpsmp/logs/archive/logCleaner.sh"
    } | crontab -
    echo "psmplogs" >psmplogs.chk
fi

echo ""
echo "*************************************************************"
echo "---- PSMP Installation Wizard Was Completed ----"
echo "*************************************************************"

echo -e "***** Some tips:" && sleep 2
echo -e "***** 1. Onboard the maintenance account we've created earlier (if not already). Best practice is to connect to it through the windows PSM component (PSM-SSH Connection Component)." && sleep 2
echo -e "***** 2. Onboard the Root account of this machine and configure the maintenance account as 'Logon Account' for it (Also as best practice we suggest reducing maint account permissions after you onboard root)." && sleep 2
echo -e "***** 3. Exlore MFA Caching capabilities: https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/PASIMP/MFA-Caching.htm" && sleep 2
echo -e "***** 4. Usage examples for PSMP: https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/privCloud-connect-using-SSH.htm#Usageexamples" && sleep 2