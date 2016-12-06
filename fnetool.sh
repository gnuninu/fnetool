#!/bin/bash
#
# SCRIPT: FNEtool
# AUTHOR: Nicola Di Marzo
# DATE: 06/12/2016
# REV: 0.1
#
# PLATFORM: Linux Centos 6.x (Netwitness L&P  10.3, 10.4 ,10.5, 10.6)
#
# PURPOSE: Troubleshooting tool for Security Analytics/Netwitness P&L licensing
# LICENSE: GNU Public License v2 (http://gnu.org/licenses/)
# Copyright (C) 2016 Nicola Di Marzo (RSA Tech CS Department EMEA UK)
#
# Parts of this code inspired by Pablo Trigo's ESAtool and IMtool: https://community.rsa.com/docs/DOC-53300
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU General Public License for more details.
#
###########################################################################################################
#
#

#SERVICE PORTS - array NwConsole

#NW_PORTS[LOG_DECODER_PORT]='50002'					#1
#NW_PORTS[LOG_DECODER_PORT_SSL]='56002:ssl'			#2
#NW_PORTS[DECODER_PORT]='50004'						#3
#NW_PORTS[DECODER_PORT_SSL]='56004:ssl'				#4
#NW_PORTS[CONCENTRATOR_PORT]='50005'				#5
#NW_PORTS[CONCENTRATOR_PORT_SSL]='56005:ssl'		#6
#NW_PORTS[BROKER_PORT]='50003'						#7
#NW_PORTS[BROKER_PORT_SSL]='56003:ssl'				#8
#NW_PORTS[ARCHIVER_PORT]='50008'					#9
#NW_PORTS[ARCHIVER_PORT_SSL]='56008:ssl'			#10
#NW_PORTS[ESA_PORT]='50030'							#11
#NW_PORTS[ESA_PORT_MONGO]='27017'					#12
#NW_PORTS[MALWARE_PORT]='60007'					    #13
#NW_PORTS[MALWARE_PORT_JMX]='60008'				    #14

#SERVICE PORTS - array REST API

#REST_PORTS[LOG_DECODER_PORT]='50102'		#1
#REST_PORTS[DECODER_PORT]='50104'			#2
#REST_PORTS[CONCENTRATOR_PORT]='50105'		#3
#REST_PORTS[BROKER_PORT]='50103'			#4
#REST_PORTS[ARCHIVER_PORT]='50108'			#5
#REST_PORTS[ESA_PORT_MONGO]='27017'			#6
#REST_PORTS[LOG_COLLECTOR_PORT]='50101'		#7


####################################
# Check if appliance phisycal or 
# virtual and define Server ID
#####################################

find_mac(){
        ls /sys/class/net | grep -i eth9 &> /dev/null
        if [ $? == 0 ] ; then
                cat /sys/class/net/eth9/address | sed 's/://g'
        else
                cat /sys/class/net/eth[0-8]/address | sed 's/://g'
        fi
}

## GLOBAL VARS

SA_SERVER_VER=`rpm -qa | grep analytics | cut -d'-' -f5 | cut -d'.' -f2`   #returns 3-4-5-6 (version)
NETWITNESS_VERS=`rpm -qa | grep analytics | cut -d'-' -f5`
#SA_IP=`ip a | grep 'inet ' | grep -v 127 | cut -d: -f2 | awk '{ print $2}' | cut -f1  -d'/'`
DATE=`date +%Y%m%d-%H%M%S`
FOLDERTMP=/tmp/$DATE
LOGS_FOLDERTMP=/tmp/fne_license_logs$DATE
TAR_DEBUG=/root/fne_license_logs$DATE.tar.gz
SA_LOG=/var/lib/netwitness/uax/logs/sa.log
FNE_LOG_DIR=/var/log/fneserver
SERVER_ID=$(find_mac)

#initial value assigned to variable opt for main menu selection
opt=" "

## ARRAYS

declare -a REST_PORTS=("50102" "50104" "50105" "50103" "50108")

RESET='\033[00;00m' # normal white

COLORS=(
    '\e[0;30m' # Black - Regular - 0
    '\e[0;31m' # Red - 1
    '\e[0;32m' # Green - 2
    '\e[0;33m' # Yellow - 3
    '\e[0;34m' # Blue - 4
    '\e[0;35m' # Purple - 5
    '\e[0;36m' # Cyan - 6
    '\e[0;37m' # White - 7
    '\e[1;30m' # Black - Bold - 8
    '\e[1;31m' # Red - 9
    '\e[1;32m' # Green - 10
    '\e[1;33m' # Yellow - 11
    '\e[1;34m' # Blue - 12
 )
 #echo -e "${COLORS[$2]}${MESSAGE}${RESET}"

## FUNCTIONS
 
restart_service(){
	service $1 restart
}

stop_service(){
	service $1 stop
}

start_service(){
	service $1 start
}

start_init_service(){
	stop $1
}

start_init_service(){
	start $1
}

####################################################
#Discover all the S/N in the system
####################################################

find_serial(){
        
        MCOCHECK=`timeout 10 mco find`
        if [[ $? != 124 ]]; then
			for nodes in $(timeout 10 mco find)
			do
                mco inventory $nodes | grep serialnumber| \
                grep -v board | cut -f 2 -d ">" |sed 's/ //g'
			done
		fi
}

#########################################################
#Check if IP inserted is correct
#########################################################

check_ip() {
   if [[ $1 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
   then
       return 0
   else
       return 1
   fi
}

###############################################
# Intro FNE script +
# Mapping
###############################################
intro_map_dlc(){
echo -e "${COLORS[12]}+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++${RESET}\n"
echo -e "${COLORS[5]}Welcome to FNEtool - ${COLORS[6]}RSA Netwitness Packets and Logs LICENSE Troubleshooting Tool${RESET}\n"
echo -e "${COLORS[12]}+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++${RESET}\n"

echo -e "Server ID detected: $SERVER_ID\n"

echo -e "${COLORS[3]}Please consult the official documentation available on this link: https://sadocs.emc.com/0_en-us/089_105InfCtr/140_Lic/10_SetUp/10_RegSAServ \non how to register Netwitness P&L Server ID and map the entitlements available in your RSA DOWNLOAD CENTER account: https://download.rsasecurity.com\n${RESET}"

echo -e "${COLORS[3]}NOTE: As a security measure any license mapping modification applied to your RSA DOWNLOAD CENTER will become effective at Midnight - 00:00 of everyday\nIn order to force the modification immediately please contact: ${COLORS[9]}support@rsa.com\n${RESET}" 

echo -e "Only ${COLORS[3]}Log Decoder, Packet Decoder, Concentrator, Broker, Archiver and ESA${RESET} require licenses."
echo -e "${COLORS[3]}Malware Analysis${RESET} requires license only if deployed on ${COLORS[3]}separate dedicated appliances${RESET}\n"

read -p "Press enter to continue"
}


########################################
#Intro 2 - Check connectivity to 
#rsasecurity.subscribenet.com
#########################################
check_web(){	
	#TEST CONNECTION TO RSASECURITY.XXXXX
		echo -e "\n checking connectivity to RSA DOWNLOAD CENTER..." ; timeout 15 curl --silent --head rsasecurity.subscribenet.com  | egrep "20[0-9] Found|30[0-9] Found" >/dev/null
		if [[ $? == 0 ]]; then
			# OK CONNECTION, Refresh licenses restart the service
			echo -e "${COLORS[10]}Connection to RSA DOWNLOAD CENTER successful\n${RESET}"
			echo "Performing Licensing refresh..." 
			restart_service fneserver
			else 
			 echo -e "${COLORS[9]}Unable to connect to rsasecurity.subscribenet.com port 80\n${COLORS[11]}${COLORS[3]}If this is an unexpected behaviour please check:\n1 Firewall\n2 DNS\n3 Proxy server\n"
			echo -e "Manual sync with RSA Download Center is required \nConsult our Official documentation on how to perform this action and how to generate and upload a license BIN file: https://sadocs.emc.com/0_en-us/089_105InfCtr/140_Lic/10_SetUp/10_RegSAServ${RESET}\n"
		fi
	read -p "Press enter to continue"
}

########################################
#Define License service 
#
#########################################

define_service10.4(){

echo -e "\nLog Decoder: 1\nPacket Decoder: 2\nConcentrator: 3\nBroker: 4\nArchiver: 5\n"
read -p "Choose a service affected by the License issueby selecting a number from 1 to 5, [enter] to return to menu or ctrl-c to exit the script:" service_number_rest
if [[ $service_number_rest = [1-5] ]]; then
	define_license_service
    premenu_ip_password
elif [[ $service_number_rest = "" ]] ; then
	return 0
else
	define_service10.4
fi
}

define_service10.4_deblogs(){
echo -e "\nLog Decoder: 1\nPacket Decoder: 2\nConcentrator: 3\nBroker: 4\nArchiver: 5\nESA: 6\nMalware Analysis: 7"
read -p "Choose a service, select a number from 1 to 7:" service_number_rest
if [[ $service_number_rest = [1-5] ]]; then
	premenu_ip_password
fi
define_license_service
}

define_service10.5(){

echo -e "\nLog Decoder: 1\nPacket Decoder: 2\nConcentrator: 3\nBroker: 4\nArchiver: 5\nESA: 6\nMalware Analysis: 7"
read -p "Choose a service, select a number from 1 to 7:" service_number_rest
if [[ $service_number_rest = [1-7] ]]; then
	define_license_service
elif [[ $service_number_rest = "" ]] ; then
	return 0
else
	define_service10.5
fi
}

####################################
# 10.4 Define IP
# and Admin Password
####################################

premenu_ip_password(){
read -p "Insert the Ip Address of the $SERVICE_TO_LICENSE:" ipaddress
check_ip $ipaddress
until [[ $? = 0 ]] ;
   do
        echo -e IP: $1
   read -p "Ip address format looks wrong, Please insert the correct IP:" ipaddress
       check_ip $ipaddress
done

echo -e "Please insert the SA/Netwitness Packets and Logs $SERVICE_TO_LICENSE service ADMIN password:" ;
read -s adminpassword

}


####################################
# Define Variables for services
# affected by the License issue
#####################################

define_license_service(){
	case $service_number_rest in
		1) 
			SERVICE_TO_LICENSE="logdecoder"
		;;
		2)
			SERVICE_TO_LICENSE="decoder"
		;;
		3)
			SERVICE_TO_LICENSE="concentrator"
		;;
		4)	
			SERVICE_TO_LICENSE="broker"
		;;
		5)
			SERVICE_TO_LICENSE="archiver"
		;;
		6)
			SERVICE_TO_LICENSE="esa"
		;;
		7)
			SERVICE_TO_LICENSE="malware-analysis"
		;;
	esac
}

#####################################################
#LicInfo and Stats service 10.4
#####################################################

licInfo_stats10.4(){
case $service_number_rest in
        1)
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[0]}"/sys/license?msg=licInfo" 2> /dev/null > $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[0]}"/sys/license?msg=licInfo" > $LOGS_FOLDERTMP/licInfo_stats.txt ;
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[0]}"/sys/license/stats" 2> /dev/null >> $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[0]}"/sys/license/stats" >> $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
        2)  
		    timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[1]}"/sys/license?msg=licInfo" 2> /dev/null > $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[1]}"/sys/license?msg=licInfo" > $LOGS_FOLDERTMP/licInfo_stats.txt ;
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[1]}"/sys/license/stats" 2> /dev/null >> $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[1]}"/sys/license/stats" >> $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
		3)  
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[2]}"/sys/license?msg=licInfo" 2> /dev/null > $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[2]}"/sys/license?msg=licInfo" > $LOGS_FOLDERTMP/licInfo_stats.txt ;
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[2]}"/sys/license/stats" 2> /dev/null >> $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[2]}"/sys/license/stats" >> $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
		4)  
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[3]}"/sys/license?msg=licInfo" 2> /dev/null > $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[3]}"/sys/license?msg=licInfo" > $LOGS_FOLDERTMP/licInfo_stats.txt ;
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[3]}"/sys/license/stats" 2> /dev/null >> $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[3]}"/sys/license/stats" >> $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
		5)    
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[4]}"/sys/license?msg=licInfo" 2> /dev/null > $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[4]}"/sys/license?msg=licInfo" > $LOGS_FOLDERTMP/licInfo_stats.txt ;
			timeout 15 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[4]}"/sys/license/stats" 2> /dev/null >> $LOGS_FOLDERTMP/licInfo_stats.txt || \
			timeout 15 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[4]}"/sys/license/stats" >> $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
		6)    
			echo -e "$SERVICE_TO_LICENSE has not Rest API available, no info gathered" > $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
		7)    
			echo -e "$SERVICE_TO_LICENSE has not Rest API available, no info gathered" > $LOGS_FOLDERTMP/licInfo_stats.txt
		;;
		*)
			echo -e "No device selected" > $LOGS_FOLDERTMP/licInfo_stats.txt
		
esac
}

####################################################
# Reset the license SERVICE 10.4
#
#####################################################

reset_device_lic_10_4(){

define_service10.4

        case $service_number_rest in
        1)
            echo -e "License to reset: "$SERVICE_TO_LICENSE" \n"
            read -p "Do you wish to continue? [y/N]: " yn
            case $yn in
            [yY][eE][sS]|[yY])
                timeout 20 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[0]}"/sys/license?msg=delAll" &> /dev/null
                case $? in
					0)
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
					;;
					35)
						timeout 20 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[0]}"/sys/license?msg=delAll" &> /dev/null
						if [[ $? = 0 ]] ; then
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
						read -p "Press enter to Return to the Main Menu"
						fi
					;;
					*)
						echo -e "${COLORS[9]}Problems connecting to the Device detected ${RESET}\n"
						echo -e "Please check if:\n1 Netwitness ADMIN password is correct \n2 $SERVICE_TO_LICENSE is running\n3 Port ${REST_PORTS[4]} is accessible\n4 $SERVICE_TO_LICENSE appliance is reachable"
						read -p "Do you want to try again? [y/N]" reset_try_yn
						case $reset_try_yn in
						[yY][eE][sS]|[yY])
							reset_device_lic_10_4
							;;
						*)
							echo "Returning to the FNEtool main menu..."
							read -p "Press enter to Return to the Main Menu"
						;;
						esac
					esac
                ;;
		    *)
				echo "Exiting...returning to the FNEtool Main Menu..."
				read -p "Press enter to Return to the Main Menu"
				;;
            esac
			;;
        2)
            echo -e "License to reset: "$SERVICE_TO_LICENSE" \n"
            read -p "Do you wish to continue? [y/N]: " yn
            case $yn in
            [yY][eE][sS]|[yY])
                timeout 20 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[1]}"/sys/license?msg=delAll" &> /dev/null
                case $? in
					0)
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
					;;
					35)
						timeout 20 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[1]}"/sys/license?msg=delAll" &> /dev/null
						if [[ $? = 0 ]] ; then
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
						read -p "Press enter to Return to the Main Menu"
						fi
					;;
					*)
						echo -e "${COLORS[9]}Problems connecting to the Device detected ${RESET}\n"
						echo -e "Please check if:\n1 Netwitness ADMIN password is correct \n2 $SERVICE_TO_LICENSE is running\n3 Port ${REST_PORTS[4]} is accessible\n4 $SERVICE_TO_LICENSE appliance is reachable"
						read -p "Do you want to try again? [y/N]" reset_try_yn
						case $reset_try_yn in
						[yY][eE][sS]|[yY])
							reset_device_lic_10_4
							;;
						*)
						echo "Returning to the FNEtool main menu..."
						read -p "Press enter to Return to the Main Menu"
						;;
						esac
					esac
                ;;
		    * )
				echo "Exiting...returning to the FNEtool Main Menu..."
				read -p "Press enter to Return to the Main Menu"
				;;
            esac
			;;
		3)
            echo -e "License to reset: "$SERVICE_TO_LICENSE" \n"
            read -p "Do you wish to continue? [y/N]: " yn
            case $yn in
            [yY][eE][sS]|[yY])
                timeout 20 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[2]}"/sys/license?msg=delAll" &> /dev/null
                case $? in
					0)
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
					;;
					35)
						timeout 20 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[2]}"/sys/license?msg=delAll" &> /dev/null
						if [[ $? = 0 ]] ; then
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
						read -p "Press enter to Return to the Main Menu"
						fi
					;;
					*)
						echo -e "${COLORS[9]}Problems connecting to the Device detected ${RESET}\n"
						echo -e "Please check if:\n1 Netwitness ADMIN password is correct \n2 $SERVICE_TO_LICENSE is running\n3 Port ${REST_PORTS[4]} is accessible\n4 $SERVICE_TO_LICENSE appliance is reachable"
						read -p "Do you want to try again? [y/N]" reset_try_yn
						case $reset_try_yn in
						[yY][eE][sS]|[yY])
							reset_device_lic_10_4
							;;
						*)
							echo "Returning to the FNEtool main menu..."
							read -p "Press enter to Return to the Main Menu"
						;;
						esac
					esac
                ;;
		    *)
				echo "Exiting...returning to the FNEtool Main Menu..."
				read -p "Press enter to Return to the Main Menu"
				;;
            esac
			;;
		4)
            echo -e "License to reset: "$SERVICE_TO_LICENSE" \n"
            read -p "Do you wish to continue? [y/N]: " yn
            case $yn in
            [yY][eE][sS]|[yY])
                timeout 20 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[3]}"/sys/license?msg=delAll" &> /dev/null
                case $? in
					0)
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
					;;
					35)
						timeout 20 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[3]}"/sys/license?msg=delAll" &> /dev/null
						if [[ $? = 0 ]] ; then
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
						read -p "Press enter to Return to the Main Menu"
						fi
					;;
					*)
						echo -e "${COLORS[9]}Problems connecting to the Device detected ${RESET}\n"
						echo -e "Please check if:\n1 Netwitness ADMIN password is correct \n2 $SERVICE_TO_LICENSE is running\n3 Port ${REST_PORTS[4]} is accessible\n4 $SERVICE_TO_LICENSE appliance is reachable"
						read -p "Do you want to try again? [y/N]" reset_try_yn
						case $reset_try_yn in
						[yY][eE][sS]|[yY])
							reset_device_lic_10_4
							;;
						*)
							echo "Returning to the FNEtool main menu..."
							read -p "Press enter to Return to the Main Menu"
						;;
						esac
					esac
                ;;
		    *)
				echo "Exiting...returning to the FNEtool Main Menu..."
				read -p "Press enter to Return to the Main Menu"
				;;
            esac
			;;
		5)
            echo -e "License to reset: "$SERVICE_TO_LICENSE" \n"
            read -p "Do you wish to continue? [y/N]: " yn
            case $yn in
            [yY][eE][sS]|[yY])
                timeout 20 curl -k -s -u "admin":$adminpassword "https://"$ipaddress":"${REST_PORTS[4]}"/sys/license?msg=delAll" &> /dev/null
                case $? in
					0)
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
					;;
					35)
						timeout 20 curl -s -u "admin":$adminpassword "http://"$ipaddress":"${REST_PORTS[4]}"/sys/license?msg=delAll" &> /dev/null
						if [[ $? = 0 ]] ; then
						echo -e "${COLORS[10]}Device Reset successful \n${COLORS[11]}Please Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service \n${RESET}Restart the ${COLORS[11]}$SERVICE_TO_LICENSE${RESET} if you still have problems to license the Service"
						read -p "Press enter to Return to the Main Menu"
						fi
					;;
					*)
						echo -e "${COLORS[9]}Problems connecting to the Device detected ${RESET}\n"
						echo -e "Please check if:\n1 Netwitness ADMIN password is correct \n2 $SERVICE_TO_LICENSE is running\n3 Port ${REST_PORTS[4]} is accessible\n4 $SERVICE_TO_LICENSE appliance is reachable"
						read -p "Do you want to try again? [y/N]" reset_try_yn
						case $reset_try_yn in
						[yY][eE][sS]|[yY])
							reset_device_lic_10_4
							;;
						*)
							echo "Returning to the FNEtool main menu..."
							read -p "Press enter to Return to the Main Menu"
						;;
						esac
					esac
                ;;
		   *)
				echo "Exiting...returning to the FNEtool Main Menu..."
				read -p "Press enter to Return to the Main Menu"
				;;
        esac
       esac
        
}

########################################################
#Print ESA and malware license reset 10.4
########################################################

reset_esa_malware10.4(){
	
echo -e "RESET ${COLORS[10]}ESA${RESET} LICENSE\n"

echo -e "Perform ESA license reset from Netwitness UI"
echo -e "${COLORS[11]}1) Reset the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Reset ${RESET}"
echo -e "${COLORS[11]}2) Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service${RESET}\n"
echo -e "If you have problems with the UI please try to reset ESA manually:"
echo -e "${COLORS[11]}1) Login to the affected ESA using SSH and run the following commands${RESET}"
echo -e "${COLORS[11]}2) /etc/init.d/rsa-esa stop${RESET}"
echo -e "${COLORS[11]}3) rm -fr /tmp/esa_backup && mkdir -p /tmp/esa_backup/${RESET}"
echo -e "${COLORS[11]}4) mv /opt/rsa/esa/trustedStorage /tmp/esa_backup${RESET}"
echo -e "${COLORS[11]}5) mv /etc/netwitness/ng/nwmaster9.bin /tmp/esa_backup${RESET}"
echo -e "${COLORS[11]}6) /etc/init.d/rsa-esa start${RESET}\n"
			
echo -e "Restart ${COLORS[11]}ESA${RESET} service if you still have problems to license the Service${RESET}\n"
echo -e "${COLORS[11]}/etc/init.d/rsa-esa restart${RESET}\n"

echo -e "RESET ${COLORS[10]}MALWARE-ANALYSIS${RESET} LICENSE\n"

echo -e "Perform Malware-analysis license reset from Netwitness UI"
echo -e "${COLORS[11]}1) Reset the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Reset ${RESET}"
echo -e "${COLORS[11]}2) Entitle the Service in the SA/Netwitness UI under Administration-->Services-->Select $SERVICE_TO_LICENSE-->Licenses Menu-->Entitle service${RESET}\n"
			
echo -e "Restart ${COLORS[11]}malware-analysis${RESET} from SA/Netwitness Head service if you still have problems to license the Service${RESET}\n"
echo -e "${COLORS[11]}restart rsaMalwareDevice${RESET}\n"

read -p "Press enter to Return to the Main Menu"
}

######################################################
# FNEserver full reset 10.4
######################################################

reset_fneserver_lic_10.4(){
read -p "Do you want to proceed with the full License server reset? [y/N]:" reset_yn
#echo -e "${COLORS[3]}Please make sure to back up the current entitlements state first under Administration-->System-->Licensing section-->Click SAVE from the Entitlements TAB${RESET}\n"
#read -p "Press enter to continue"
	case $reset_yn in
		[yY][eE][sS]|[yY])
			echo -e "${COLORS[3]}Please make sure to back up the current entitlements state first under Administration-->System-->Licensing section-->Click SAVE from the Entitlements TAB${RESET}\n"
			echo -e "${COLORS[3]}A backup of files will be performed in /tmp directory as well${RESET}"
			read -p "Press enter to continue"
			stop_service fneserver &&
			LD_LIBRARY_PATH=/lib:/lib64:/usr/lib:/usr/lib64:/usr/local/lib:/opt/fneserver/lib:/usr/bin/lic ; export LD_LIBRARY_PATH &&
			/opt/fneserver/bin/fneserver reset
			echo -e "Backing up old entitlements to /tmp folder...and restart license service"
			mkdir -p ${FOLDERTMP}old_entitlements && mv /var/lib/fneserver/ra* ${FOLDERTMP}old_entitlements &&
			start_service fneserver;
			if [ $? == 0 ]; then
			echo -e "${COLORS[10]}Reset Successful\n${COLORS[11]}Refresh Entitlements under Administration-->System-->Licensing section-->Click on Refresh button from the top Menu\n${RESET}"
			echo -e "If you are not able to connect to rsasecurity.subscribenet.com upload a new license BIN file as described here: https://sadocs.emc.com/0_en-us/089_105InfCtr/140_Lic/10_SetUp\nthen click refresh from the Licensing section"
			read -p "Press enter to Return to the Main Menu"
			main_menu
			else
			echo -e "${COLORS[9]}Problems encountered while resetting the License/n ...Exiting please try again.${RESET}"
			read -p "Press enter to Return to the Main Menu"
		    fi
		;;
		*)
			echo "Returning to the main menu..."
			read -p "Press enter to Return to the Main Menu"
		;;
	esac	
}

######################################################
# Collect Logs and statistics 10.4 
######################################################

debug_logs_10.4(){
define_service10.4_deblogs
echo -e "Collecting logs and Statistcs and creating related file "$TAR_DEBUG" under /root...please wait\n"
mkdir -p $LOGS_FOLDERTMP ;
cp $FNE_LOG_DIR/* $LOGS_FOLDERTMP ;
wget -O - -o /dev/null http://127.0.0.1:3333/fne/xml/properties | xmllint --format - 2> /dev/null > $LOGS_FOLDERTMP/properties.xml ;
wget -O - -o /dev/null http://127.0.0.1:3333/fne/xml/reservations | xmllint --format - 2> /dev/null > $LOGS_FOLDERTMP/reservations.xml ;
wget -O - -o /dev/null http://127.0.0.1:3333/fne/xml/features | xmllint --format - 2> /dev/null > $LOGS_FOLDERTMP/features.xml ;
wget -O - -o /dev/null http://127.0.0.1:3333/fne/xml/devices | xmllint --format - 2> /dev/null > $LOGS_FOLDERTMP/devices.xml ;
wget -O - -o /dev/null http://127.0.0.1:3333/fne/xml/diagnostics | xmllint --format - 2> /dev/null > $LOGS_FOLDERTMP/diagnostics.xml ;

licInfo_stats10.4
find_serial > $LOGS_FOLDERTMP/serial_numbers.txt;
echo "$SERVER_ID" > $LOGS_FOLDERTMP/server_id.txt

tar czvf $TAR_DEBUG -C $LOGS_FOLDERTMP .


echo -e ""${COLORS[10]}$TAR_DEBUG" has been created in /root, you can remove $LOGS_FOLDERTMP and its content running:${RESET}\n\

${COLORS[11]}rm -rf $LOGS_FOLDERTMP/*\nrmdir $LOGS_FOLDERTMP${RESET}"

read -p "Press enter to Return to the Main Menu"

}

######################################################
# Collect Logs and statistics 10.5/6
######################################################

debug_logs_10.5(){

echo -e "In order to increase the ${COLORS[11]}debug verbosity${RESET}, make sure to set the Log Level to debug (hit Apply) in the"
echo -e "SA/Netwitness ${COLORS[11]}Administration > System > System Logging > Settings for the following packages:"
echo -e "com.rsa.smc.sa.admin.service.entitlement.DefaultEntitlementService${RESET} and ${COLORS[11]} com.rsa.smc.sa.core.licensing${RESET}\n"

read -p "Press enter to continue"

echo -e "Restarting fneserver..."
restart_service fneserver;
sleep 2;
echo -e "Collecting logs and Statistcs and creating related file "$TAR_DEBUG" under /root...please wait\n"
mkdir -p $LOGS_FOLDERTMP ;
cp $FNE_LOG_DIR/* $LOGS_FOLDERTMP ;
cp $SA_LOG $LOGS_FOLDERTMP;

echo 'db.entitlement.find().pretty()' | mongo sa > $LOGS_FOLDERTMP/entitlements.txt;

find_serial > $LOGS_FOLDERTMP/serial_numbers.txt;
echo "$SERVER_ID" > $LOGS_FOLDERTMP/server_id.txt;

tar czvf $TAR_DEBUG -C $LOGS_FOLDERTMP .

echo -e ""${COLORS[10]}$TAR_DEBUG" has been created in /root, you can remove $LOGS_FOLDERTMP and its content running:${RESET}\n\

${COLORS[11]}rm -rf $LOGS_FOLDERTMP/*\nrmdir $LOGS_FOLDERTMP${RESET}"

read -p "Press enter to Return to the Main Menu"

}


####################################################
#Check/remove entitlements from MongoDB
####################################################

mongo_remove(){
echo -e "Restarting fneserver..."
	restart_service fneserver;
	sleep 2;

OBJECT_ID=`tail -n 100 "$SA_LOG" | grep -i "DefaultEntitlementService - Couldn't get endpoint with ID" | awk '{print $12}'|sort|uniq -w 24`
if [[ -n $OBJECT_ID ]] ; then
	echo -e "Restarting fneserver...";
	echo -e "Discovered following services that can be deleted from the database:\n${COLORS[10]}$OBJECT_ID${RESET}"
	echo -e "run the following commands to complete the deletion:\n"
		for ID in $(tail -n 100 "$SA_LOG" | grep -i "DefaultEntitlementService - Couldn't get endpoint with ID" | awk '{print $12}'|sort|uniq -w 24) ; do	
		echo -e "${COLORS[3]}echo 'db.entitlement.remove( { _id: ObjectId(\""$ID"\") } )' | mongo sa${RESET}"
		done
	read -p "Press enter to Return to the Main Menu"
else
	read -p "No entilements to remove found, press enter to Return to the Main Menu"
fi
}

##################################################
#Show Mongo Entitlements collection
##################################################
mongo_entitlements_coll(){
	
read -p "Press enter to view the entitlements and "q" to exit less editor"

echo 'db.entitlement.find().pretty()' | mongo sa | less

read -p "Press enter to Return to the Main Menu"

}

####################################################
# Server ID/MAC Address change/troubleshooting tips
#
####################################################

server_id_mac_issue(){

echo -e "If you need to change the ${COLORS[10]}Server ID (Current:$SERVER_ID)${RESET}due to a reimage or a NIC replacement on a ${COLORS[11]}physical appliance${RESET}"
echo -e "or simply to avoid license ID duplicate conflicts, a re-mapping of the ${COLORS[11]} ETH9 virtual bridge${RESET} may be required\n"

echo -e "${COLORS[11]}Please consult this Knowledge Base Article available on RSA Link with full info on the matter: https://community.rsa.com/docs/DOC-53329\n${RESET}"

echo -e "If you are using a ${COLORS[11]}virtual SA/Netwitness Head ${RESET}in order to change the Server ID you would need to ${COLORS[11]}change the MAC ADDRESS of yor Virtual Machine${RESET}"
echo -e "Please conuslt VMware or your virtualization solution documentation for more details on how to change the MAC ADDRESS\n"

echo -e "${COLORS[11]}NOTE After you change the Server ID you need to register the new one on your RSA DOWNLOAD CENTER portal${RESET}"
echo -e "Please consult the official documentation available on this link: https://sadocs.emc.com/0_en-us/089_105InfCtr/140_Lic/10_SetUp/10_RegSAServ"
echo -e "on how to register Netwitness P&L Server ID and map the entitlements available in your RSA DOWNLOAD CENTER account: https://download.rsasecurity.com\n"

read -p "Press enter to Return to the Main Menu"
}

######################################################
#Red Banner warning issue 10.5/6
######################################################

red_banner(){

echo -e "If you are using ${COLORS[10]}Meter Licenses SIEM, NetMon and Malware applied to Decoders and Malware, those will cover also all your SA/Netwitness environment${RESET}"
echo -e "as soon as you don't overexceed the limit of traffic/log allowed by your meter license purchase\n"

echo -e "However, ${COLORS[11]}there might be cases where the Red Banner appears persistently in the UI${RESET}"
echo -e "In this case ${COLORS[11]}we highly recommend to upgrade to Netwitness patches 10.6.1.1 and 10.5.2.1 in order to fix this issue"
echo -e "All the details available on RSA Link: https://community.rsa.com/docs/DOC-53397${RESET}\n"

echo -e "${COLORS[11]}For Red Banner issues related with SA/Netwitness multi-deployment please consult this document: https://community.rsa.com/docs/DOC-45204${RESET}\n"

echo -e "For any further info about the new Netwitness Meter and Trust License Model, please ${COLORS[11]}consult our official licensing guide: https://community.rsa.com/docs/DOC-60751${RESET}"

read -p "Press enter to Return to the Main Menu"
}

####################################################
#persistent problems uploading license BIN file
####################################################

problems_upload_bin(){
	
echo -e "Follow the below procedure if you have persistent problems uploading a license BIN file from the UI\n"
	
echo -e "${COLORS[11]}1 download an offline capability request from Administration-->System-->licensing section"
echo -e "2 generate a new license BIN response file as described here(do not upload it now): https://sadocs.emc.com/0_en-us/089_105InfCtr/140_Lic/10_SetUp/10_RegSAServ"
echo -e "3 jettysrv stop"
echo -e "4 service puppet stop" 
echo -e "5 service fneserver stop" 
echo -e "6 rm -rf /var/lib/fneserver/ra*"
echo -e "7 echo 'db.entitlement.remove()' | mongo sa"
echo -e "8 service fneserver start"
echo -e "9 service puppet start"
echo -e "10 jettysrv start"
echo -e "11 Upload the response BIN file on Administration-->System-->licensing section"
echo -e "12 Refresh the license.\n"

echo -e "Note that in step 1 only the download of the capability request needs to be performed.${RESET}\n"

read -p "Press enter to Return to the Main Menu"

}

####################################################
# FNEtool Menu 
# displayed by version detected
####################################################
main_menu(){
clear

if [[ $SA_SERVER_VER == 3 || $SA_SERVER_VER == 4 ]]; then
echo -e "${COLORS[12]}+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++${RESET}\n"
echo -e "${COLORS[5]}     FNEtool - ${COLORS[6]}Main Menu - Netwitness P&L "$NETWITNESS_VERS" ${RESET}\n"
echo -e "${COLORS[12]}+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++${RESET}\n"
  #echo -e "** 0) Select/Configure a Service affected by License issue"
  echo -e "** 0) Reset Core and Archiver License Services"
  echo -e "** 1) Reset ESA and Malware Analysis license Services"
  echo -e "** 2) Reset FNE license Server"
  echo -e "** 3) Change Server ID/Mac Address"
  #echo -e "** 4) Print Statistics and license Info"
  echo -e "** 4) Collect logs for RSA Support"
  echo -e "** 5) Persistent problems uploading manual license BIN file in the UI\n"
  
  echo -e "Ideal troubleshooting sequence order in case of a ${COLORS[11]}service unlicensed${RESET} after refreshing licenses or uploading capability response BIN file:\n"
  echo -e "Re-entitle the service from Services section-->Licenses, reset service, restart service"
  echo -e "Administration-->System-->Licensing-->refresh, reset fneserver (save config), refresh license or upload BIN file, re-entitle service, restart jetty as last resort\n"

elif [[ $SA_SERVER_VER == 5 || $SA_SERVER_VER == 6 ]]; then
echo -e "${COLORS[12]}+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++${RESET}\n"
echo -e "${COLORS[5]}     FNEtool - ${COLORS[6]}Main Menu - Netwitness P&L "$NETWITNESS_VERS" ${RESET}\n"
echo -e "${COLORS[12]}+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++${RESET}\n"
  #echo -e "** 0) Select a Service affected by License issue"
  #echo -e "** 0) Run a scan for service licensing issues"
  echo -e "** 0) Detect/Remove Entitlements from the Database (Service based license)"
  echo -e "** 1) Change Server ID/Mac Address"
  echo -e "** 2) Problems with the Red Banner in the UI (Meter License}"
  echo -e "** 3) Print Entitlements collection and license Info"
  echo -e "** 4) Collect logs for RSA Support"
  echo -e "** 5) Persistent problems uploading manual license BIN file in the UI"
else
 echo -e "Other Versions detected... exiting"
 exit 1
fi

  echo -e "Please enter a menu ${COLORS[11]}option number${RESET} or enter to exit."
  read -e opt
}

intro_map_dlc
check_web

if [[ $SA_SERVER_VER == 3 || $SA_SERVER_VER == 4 ]]; then
      while [ opt != '' ]
        do
        if [[ $opt = '' ]]; then
                exit;
		else
		main_menu
            case $opt in
            0) clear;
				echo -e "Option 0 Selected - Reset Core/Archiver license service";
				reset_device_lic_10_4;
				;;
			1) clear;
                echo -e "Option 1 Selected - Reset ESA/Malware license services";
                reset_esa_malware10.4
                ;;
			2) clear;
				echo -e "Option 2 Selected - Reset FNEServer";
                reset_fneserver_lic_10.4;
                ;;
            3) clear;
				echo -e "Option 2 Selected - Change Server ID";
                server_id_mac_issue
                ;;
            4) clear;
                echo -e "Option 4 Selected - Collect Logs";
				debug_logs_10.4;
                ;;
            5) clear;
                echo -e "Option 5 Selected - Problems uploading license BIN File";
				problems_upload_bin;
                ;;
			x) exit;
				;;
            \n) exit;
				;;
			*)clear;
				echo -e "Select an option from the menu, ctrl-c to exit the script";
				;;
		esac
       fi
done
elif [[ $SA_SERVER_VER == 5 || $SA_SERVER_VER == 6 ]]; then
      while [ opt != '' ]
        do
        if [[ $opt = '' ]]; then
                exit;
		else
		main_menu
            case $opt in
			0) clear;
                echo -e "Option 0 Selected - Remove Entitlements";
                mongo_remove;
                ;;
			1) clear;
				echo -e "Option 1 Selected - Change Server ID";
                server_id_mac_issue;
                ;;
            2) clear;
                echo -e "Option 2 Selected - Red Banner issue";
				red_banner;
                ;;
            3) clear;
                echo -e "Option 3 Selected - Display entitlements";
				mongo_entitlements_coll;
				;;
			4) clear;
                echo -e "Option 4 Selected - Collect Logs";
				debug_logs_10.5;
                ;;
            5) clear;
                echo -e "Option 5 Selected - Problems uploading license BIN File";
				problems_upload_bin;
                ;;
			x) exit;
				;;
            \n) exit;
				;;
			*)clear;
				echo -e "Select an option from the menu, ctrl-c to exit the script";
				;;
		esac
       fi
done
else
  echo -e "UNSUPPORTED VERSION! Aborting..."
  exit 1
fi
		

