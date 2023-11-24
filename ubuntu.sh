#!/bin/bash

check_root() {

    if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
    fi

}


check_root

# Color pattern for PASS and FAIL
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
flag=$1
backup="$(date +%F_%T)"

# Define file paths
file_modprobe="/etc/modprobe.d/CIS.conf"
file_sshd="/etc/ssh/sshd_config"
file_audit="/var/log/audit"
file_rsyslog="/etc/rsyslog.conf"
file_passwd="/etc/passwd"
file_logrotate="/etc/cron.daily/logrotate"
file_shadow="/etc/shadow"
file_gshadow="/etc/gshadow"
file_journal="/var/log/journal"
pam_su="/etc/pam.d/su"

# Backup configs and create log file to record changes
cp $file_sshd $file_sshd.$backup
cp $file_passwd $file_passwd.$backup
cp $file_shadow $file_shadow.$backup
cp $file_gshadow $file_gshadow.$backup
cp $pam_su $pam_su.$backup
mkdir -p $file_audit

# Define the directories
directories=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d" "/etc/shadow")

# Define the unnecessary filesystems, protocols
unnecessary_modules=("hfsplus" "hfs" "freevxfs" "jffs" "cramfs" "tipc" "sctp" "dccp" "rds" "usb-storage")

# Get a list of all accounts
users=$(cat $file_passwd | cut -d: -f1)
system_accounts=$(awk -F: '($3 < 500) {print $1 }' $file_passwd)

# Get the path to the grub.cfg file
file_grub_cfg=$(find /boot -type f -name 'grub.cfg')

permissions() {

    # Set the owner and group to root, and permissions to 0700 for each directory
    for directory in "${directories[@]}"; do
    # Check if the directory exists
    if [ -d "$directory" ] ; then

        check_dir "$directory"

        # Check if the owner and group are set to root
        if [[ $dir_owner != "root" || $dir_group != "root" ]]; then
            
            if [[ $flag != "-y" ]]; then
                echo -e "${YELLOW} Do you want to set the owner and group to root for $directory ${NC}"
                read input    
            fi    

            if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
                # Change the owner and group to root  
                chown root:root "$directory"
                echo -e "${GREEN}[ PASS => Set the owner and group to root for $directory ] ${NC}"
                echo "Owner and group for $directory are configured." >> $file_audit/audit.log
            else
                echo -e "${RED}[ FAIL => Set the owner and group to root for $directory ] ${NC}"
            fi
        else
            echo -e "${GREEN}[ PASS => Set the owner and group to root for $directory ] ${NC}"
        fi

        # Check if the permissions are set to 0700
        if [[ $dir_perms != "700" ]]; then

            if [[ $flag != "-y" ]]; then
                echo -e "${YELLOW} Do you want to set permissions to 0700 for $directory ${NC}"
                read input
            fi

            if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
                # Set permissions to 0700
                chmod 0700 "$directory"
                echo -e "${GREEN}[ PASS => Set the permissions to 0700 for $directory ] ${NC}"
                echo "Permissions for $directory are configured." >> $file_audit/audit.log
            else
                echo -e "${RED}[ FAIL => Set the permissions to 0700 for $directory ] ${NC}"
            fi
        else
            echo -e "${GREEN}[ PASS => Set the permissions to 0700 for $directory ] ${NC}"
        fi
        

    elif [ "$directory" == "$file_shadow" ] ; then

        check_dir "$directory"

        if [[ $dir_perms != "0" ]]; then

            if [[ $flag != "-y" ]]; then
                echo -e "${YELLOW} Do you want to set permissions to 0000 for $directory ${NC}"
                read input
            fi
            
            if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
                # Set permissions to 0000 for /etc/shadow file
                chmod 0000 "$file_shadow"
                echo -e "${GREEN}[ PASS => Set the permissions to 0000 for $directory ] ${NC}"
                echo "Permissions for $directory are configured." >> $file_audit/audit.log
            else
                echo -e "${RED}[ FAIL => Set the permissions to 0000 for $directory ] ${NC}"
            fi
        else
            echo -e "${GREEN}[ PASS => Set the permissions to 0000 for $directory ] ${NC}"
        fi

    else
        echo "$directory does not exist."
    fi
    done

    


}

check_dir() {

    # Get the owner and group of the directory
    dir_owner=$(stat -c '%U' $1)
    dir_group=$(stat -c '%G' $1)

    # Get the permissions of the directory
    dir_perms=$(stat -c '%a' $1)

}

home_dir_permission()   {

    # Iterate over the list of users home directories
    for user in $users; do
        home_dir=$(getent passwd "$user" | cut -d: -f6)
        if [ -d "$home_dir" ]; then
            dirperm=$(stat -L -c '%A' "$home_dir")
            if [ "$(echo "$dirperm" | cut -c6)" != '-' ] || [ "$(echo "$dirperm" | cut -c8)" != '-' ] || [ "$(echo "$dirperm" | cut -c9)" != '-' ] || [ "$(echo "$dirperm" | cut -c10)" != '-' ]; then
                if [[ $flag != "-y" ]]; then
                    echo -e "${YELLOW} Do you want to set permissions to 750 for $home_dir ${NC}"
                    read input
                fi    

                if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
                    # Set user home directories to 750 permission
                    chmod 750 "$home_dir"
                    echo -e "${GREEN}[ PASS => Set the permissions to 750 for $home_dir ] ${NC}"
                    echo "Configuring $home_dir to 750 permission is complete." >> $file_audit/audit.log
                else
                    echo -e "${RED}[ FAIL => Set the permissions to 750 for $home_dir ] ${NC}"
                fi            
            fi            
        fi
    done


}

# nologin_shell()   {
#     # Iterate over the list of system accounts and set their shells to /sbin/nologin
#     for account in $system_accounts; do
#         shell=$(getent passwd $account | cut -d: -f7)
#         if [[ "$account" != "root" && "$shell" = "$(which nologin)" ]]; then
#             if [[ $flag != "-y" ]]; then
#                 echo -e "${YELLOW} Do you want to set $account to nologin shell ? ${NC}"
#                 read input
#             fi    

#             if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
#                 usermod -s $(which nologin) "$account"
#                 echo -e "${GREEN}[ PASS => Set $account to non-login ] ${NC}"
#                 echo "Set $account to non-login is complete." >> $file_audit/audit.log
#             else
#                 echo -e "${RED}[ FAIL => Set $account to nologin ] ${NC}"
#             fi
#         else
#             echo -e "${GREEN}[ PASS => Set $account to nologin ] ${NC}"
#         fi
        
#     done

# }


remove_unnecessary_account()    {

    users=$(cat $file_passwd | cut -d: -f1)
    for user in $users; do
    # Remove any accounts that are games
    if [[ $user =~ (games|steam|playonlinux|wine) ]]; then
        if [[ $flag != "-y" ]]; then
            echo -e "${YELLOW} Do you want to remove $user ? ${NC}"
            read input
        fi

        if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
            userdel -rf $user 2>/dev/null
            echo -e "${GREEN}[ PASS => Remove unnecessary $user ] ${NC}"
            echo "Removing unnecessary $user is complete." >> $file_audit/audit.log
        else
            echo -e "${RED}[ FAIL => Remove unnecessary $user ] ${NC}"
        fi
    fi
    done
    # echo -e "${GREEN}[ PASS => Remove all unnecessary accounts ] ${NC}"

}



disable_and_blacklist_module() {

    if [ ! -f $file_modprobe ]; then
        touch $file_modprobe
    fi

    # Disable and blacklist unnecessary modules
    for module_name in "${unnecessary_modules[@]}"; do    

    if ! grep -q "^install $module_name /bin/true" "$file_modprobe" ; then
        if [[ $flag != "-y" ]]; then
            echo -e "${YELLOW} Do you want to disable the $module_name? (Y/N): ${NC}"
            read input
        fi

        if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then            
            echo "install $module_name /bin/true" >> $file_modprobe
            echo -e "${GREEN}[ PASS => Disable the installation and use of $module_name that are not required ] ${NC}"
            echo "Disabling and blacklisting $module_name is done..." >> $file_audit/audit.log
        else
            echo -e "${RED}[ FAIL => Disable the installation and use of $module_name that are not required ] ${NC}"
        fi
    else
        echo -e "${GREEN}[ PASS => Disable the installation and use of $module_name that are not required ] ${NC}"
    fi
    done
}

restrict_su_access()    {
    # Check if the required configuration line exists in su PAM file
    if ! grep -qE "^auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" "$pam_su"; then
        if [[ $flag != "-y" ]]; then
            echo -e "${YELLOW} Do you want to restrict access to the root account via su to the 'root' group? (yes/no): ${NC}"
            read input
        fi

        if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
            # Find the line number of the first occurrence of the 'auth required pam_wheel.so use_uid' line
            uid_line_num=$(grep -nE "^auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" "$pam_su" | cut -d: -f1)
            append_line_num=$(grep -nE "^auth[[:space:]]*" "$pam_su" | cut -d: -f1)

            if [ -z "$uid_line_num"]; then
                # Insert the required configuration line after the found line number
                sed -i "${append_line_num} a auth required pam_wheel.so use_uid" "$pam_su"
                echo -e "${GREEN}[ PASS => Restrict access to the root account via su to the 'root' group ] ${NC}"
                echo "Restrict access to the root account is done..." >> $file_audit/audit.log
            fi
        else
            echo -e "${RED}[ FAIL => Restrict access to the root account via su to the 'root' group ] ${NC}"
        fi
    else
        echo -e "${GREEN}[ PASS => Restrict access to the root account via su to the 'root' group ] ${NC}"
    fi        

}


secure_icmp()  {

    if [[ $flag != "-y" ]]; then
        echo -e /"${YELLOW} Do you want to tuning network interface for ICMP redirect? (yes/no): ${NC}"
        read input
    fi

    if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
    # Iterate through network interfaces and disable ICMP redirects and source routed packets.
        for interface in $(ip -o link show | awk -F ': ' '{print $2}'); do
            echo "Disabling ICMP redirects for $interface..."
            sysctl -w net.ipv4.conf.all.accept_redirects=0
            sysctl -w net.ipv4.conf.default.accept_redirects=0
            sysctl -w net.ipv4.conf."$interface".accept_redirects=0
            sysctl -w net.ipv6.conf."$interface".accept_redirects=0

            echo "Disabling secure ICMP redirects for $interface..."
            sysctl -w net.ipv4.conf.all.secure_redirects=0
            sysctl -w net.ipv4.conf.default.secure_redirects=0
            sysctl -w net.ipv4.conf."$interface".secure_redirects=0
            sysctl -w net.ipv6.conf."$interface".secure_redirects=0

            echo "Disabling source routed packets for $interface..."
            sysctl -w net.ipv4.conf.all.accept_source_route=0
            sysctl -w net.ipv4.conf.default.accept_source_route=0
            sysctl -w net.ipv4.conf."$interface".accept_source_route=0
            sysctl -w net.ipv6.conf."$interface".accept_source_route=0

            echo "Disabling packet redirect sending for $interface..."
            sysctl -w net.ipv4.conf.all.send_redirects=0
            sysctl -w net.ipv4.conf.default.send_redirects=0
            sysctl -w net.ipv4.conf."$interface".send_redirects=0
            sysctl -w net.ipv6.conf."$interface".send_redirects=0

            echo "Enabling logging of martian packets for $interface..."
            sysctl -w net.ipv4.conf.all.log_martians=1
            sysctl -w net.ipv4.conf.default.log_martians=1
            sysctl -w net.ipv4.conf."$interface".log_martians=1

            echo "Enabling source validation by reverse path for $interface..."
            sysctl -w net.ipv4.conf.all.rp_filter=1
            sysctl -w net.ipv4.conf.default.rp_filter=1
            sysctl -w net.ipv4.conf."$interface".default.rp_filter=1

        done
        # Save the changes to the sysctl configuration files.
        sysctl --system
        echo -e "${GREEN}[ PASS => Tuning network interface for ICMP redirect ] ${NC}"
    else
        echo -e "${RED}[ FAIL => Tuning network interface for ICMP redirect ] ${NC}"
    fi

    # Display a completion message.
    # echo -e "${GREEN}[ PASS => All about ICMP packets have been either disabled or enabled for all interfaces. ${NC}"
    # echo "All about ICMP packets have been either disabled or enabled for all interfaces."

}


persist_log() {

    # Creating journal log file    
    if [ ! -f "$file_journal" ]; then
        if [[ $flag != "-y" ]]; then
            echo -e "${YELLOW} Do you want to enable persistent logging in systemd-journald? (yes/no): ${NC}"
            read input
        fi

        if [[ $input =~ (Y|y|Yes|YES|yes) || $flag == "-y" ]]; then
            mkdir -p $file_journal
            echo -e "${GREEN}[ PASS => Enable persistent logging in systemd-journald ] ${NC}"
            echo "Enabling persistent logging in systemd-journald..." >> $file_audit/audit.log
        else
            echo -e "${RED}[ FAIL => Enable persistent logging in systemd-journald ] ${NC}"
        fi

    else
        echo -e "${GREEN}[ PASS => Enable persistent logging in systemd-journald ] ${NC}"
    fi

}


permissions
disable_and_blacklist_module
home_dir_permission
# nologin_shell
remove_unnecessary_account
restrict_su_access
secure_icmp
persist_log
