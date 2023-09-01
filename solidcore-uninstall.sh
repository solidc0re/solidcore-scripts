#!/bin/bash

## Solidcore Hardening Scripts for Fedora's rpm-ostree Operating Systems
## Version 0.1
##
## Copyright (C) 2023 solidc0re (https://github.com/solidc0re)
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see https://www.gnu.org/licenses/.

# Uninstall script


# === DISPLAY FUNCTIONS ===

# Interruptable version for long texts
long_msg() {
    local main_output="$1"
    local idx=0
    local char

    while [ $idx -lt ${#main_output} ]; do
        char="${main_output:$idx:1}"
        echo -n "$char"
        
        # Check if a key was pressed
        if read -r -s -n 1 -t 0.01 key; then
            # Output the remaining portion of the main_output
            echo -n "${main_output:idx+1}"
            break
        fi
        
        sleep 0.015
        idx=$((idx + 1))
    done
}

# Non-interruptable version for short messages
short_msg() {
    local main_output=">  $1"
    echo
    local idx=0
    local char

    while [ $idx -lt ${#main_output} ]; do
        char="${main_output:$idx:1}"
        echo -n "$char"
        sleep 0.015
        idx=$((idx + 1))
    done
}

# Non-interruptable version for confirmation messages
GREEN='\033[0;32m'
NC='\033[0m' # No Color

conf_msg() {
    short_msg "$1"
    echo -ne " ${GREEN}✓${NC}"
}

# Create two line gap
space_2() {
    long_msg "
>
>  "
}


# Create one line gap
space_1() {
    long_msg "
>  "
}

# Declare bold and normal
bold=$(tput bold)
normal=$(tput sgr0)


# === SUDO CHECK ===
if [ "$EUID" -ne 0 ]; then
    short_msg "This script requires sudo privileges. Please run it with 'sudo' using 'sudo <path-to-script>./solidcore-uninstall.sh"
    exit 1
fi


# === INFORM USER ===
space_2
short_msg "You are about to uninstall all solidcore changes to your system."
space_1
while true; do
read -rp "${bold}Question: Do you want to continue?${normal} (y/n): " uninstall_response
case $uninstall_response in
	[Yy] ) hostname_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done
space_2

if [[ "$uninstall_response" =~ ^[Yy]$ ]]; then

	# === RESTORE BACKUPS ===
	
	# Define an array of files to be restored
	files_to_restore=(
	    "/etc/default/grub"
    	"/etc/fstab"
		"/etc/machine-id"
		"/etc/resolv.conf"
 	    "/etc/rpm-ostreed.conf"
    	"/etc/security/limits.conf"
    	"/etc/ssh/sshd_config"
    	"/etc/systemd/coredump.conf"
    	"/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf"
	    "/var/lib/dbus/machine-id"
	)

	# Loop through the array and restore backup copies
	for source_file in "${files_to_restore[@]}"; do
    	# Check if the backup file exists
    	backup_file="${source_file}_sc.bak"
    	if [ -e "$backup_file" ]; then
    	    if [ "$backup_file" == "/var/lib/dbus/machine-id"]; then
				# Restore the backup file
    	    	cp "$backup_file" "$source_file"
    	    	conf_msg "Backup restored for: $source_file"
    	    	# Remove the backup file
    	    	rm "$backup_file"
    	    	conf_msg "Machine ID restored"
			else	
				# Restore the backup file
    	    	cp "$backup_file" "$source_file"
    	    	conf_msg "Backup restored for: $source_file"
    	    	# Remove the backup file
    	    	rm "$backup_file"
			fi
    	else
	    # Check if the source file exists
    	    if [ -e "$source_file" ]; then
    	        # Check if the source file should be deleted
    	        case "$source_file" in
    	            *"/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf"*)
    	                # Delete the source file
    	                rm -f "$source_file"
    	                conf_msg "Deleted: $source_file"
    	                ;;
    	            *)
    	                ;;
    	        esac
    	    fi
    	fi
	done
	space_2
	space_1

	# Run update-grub to update GRUB configuration
	if grub2-mkconfig -o /boot/grub2/grub.cfg; then
    	conf_msg "GRUB configuration updated"
	else
    	short_msg "Failed to update GRUB configuration."
	fi
	space_2
	space_1


	# === UNMASK SERVICES ===
	services=(
    	avahi-daemon
    	cups
		geoclue
    	httpd
		network-online.target
    	nfs-server
		remote-fs.target
    	rpcbind
    	rpm-ostree-countme
    	sshd
	)

	# Loop through the array and unmask
	for service in "${services[@]}"; do
    	# Stop the service/socket
    	systemctl unmask "$service"
    	# Echo a message
    	conf_msg "$service unmasked"
	done
	space_2
	space_1

	# Stop dnscrypt-proxy
	/usr/local/sbin/dnscrypt-proxy/dnscrypt-proxy -service stop
	# Restart systemd-resolved
	systemctl enable --now systemd-resolved
	space_2
	space_1

	# === REMOVE SOLIDCORE SERVICES ===

	services_to_delete=(
		"dnscrypt-proxy-update.service"
		"dnscrypt-proxy-update.timer"
		"flatpak-update.service"
		"flatpak-update.timer"
		"solidcore-first-boot.service"
		"solidcore-second-boot.service"
	)
	
	# Loop through the array and stop and disable each service
	for service in "${services_to_delete[@]}"; do
    	# Stop the service/socket
    	systemctl stop "$service"
        # Disable the service/socket
    	systemctl disable "$service"
	    # Delete service/socket
	    rm /etc/systemd/system/"$service"
		systemctl daemon-reload
	    # Echo a message
	    conf_msg "$service disabled and deleted"
	done
	space_2
	space_1

	# === REMOVE SOLICORE CREATED SCRIPTS & CONFIGS ===

	files_to_delete=(
		"/etc/modprobe.d/solidcore-blacklist.conf"
		"/etc/profile.d/solidcore_umask.sh"
		"/etc/solidcore/solidcore-firstboot.sh"
		"/etc/solidcore/solidcore-secondboot.sh"
		"/etc/solidcore/solidcore-welcome.sh"
		#"/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf" -> deleted if exists, in 'restore backups'
		"/etc/udev/rules.d/70-titan-key.rules"
		"/etc/udev/rules.d/70-u2f.rules"
		"/etc/udev/rules.d/41-nitrokey.rules"
		"/etc/udev/rules.d/49-onlykey.rules"
		"/etc/xdg/autostart/solidcore-mute-mic.desktop"
        "/etc/xdg/autostart/solidcore-welcome.desktop"
		"/etc/xdg/autostart/solidcore-secondboot.desktop"
	)

	for file in "${files_to_delete[@]}"; do
	    # Check if the source file exists
	    if [ -e "$file" ]; then
	    # Delete file
	    rm "$file"
		systemctl daemon-reload
	    conf_msg "Solidcore created file removed: $override_file"
		fi
	done
	space_2
	space_1


	# === RESTORE SYSCTL SETTINGS ===

	# Check if the script exists
	if [ -e "/etc/solidcore/defaults.sh" ]; then
	    # Run the script
	    /etc/solidcore/defaults.sh
	    conf_msg "Sysctl settings restored"
	    # Reload sysctmctl
	    systemctl daemon-reload
	    # Remove old stored settings
	    rm /etc/solidcore/defaults.sh
	else
	    short_msg "Script /etc/solidcore/defaults.sh does not exist."
	fi
	space_2
	space_1

     # === RESTORE FEDORA FLATPAK ===

 	# Check if the script exists
	if [ -e "/etc/solidcore/fedora_flatpak.sh" ]; then
	    # Run the script
	    /etc/solidcore/fedora_flatpak.sh
	    conf_msg "Fedora Flatpaks restored"
	    # Remove flatpak undo script
	    rm /etc/solidcore/fedora_flatpak.sh
	else
	    short_msg "Script /etc/solidcore/fedora_flatpak.sh does not exist."
	fi
	space_2
	space_1


	# === REVERT PASSWORD POLICIES ===
	
	authselect select sssd
	conf_msg "Default password policies applied"
	
	rm -rf /etc/authselect/custom/solidcore*
	conf_msg "Solidcore password policies removed"

	passwd -u root
	conf_msg "root account unlocked"
	space_2
	space_1
	

	# === REVERT HOSTNAME ===
	# Check if the file exists
	if [ -f "/etc/solidcore/hostname_sc.bak" ]; then
    	# Read the hostname from backup
    	saved_hostname=$(cat "$hostname_file")
	    # Revert hostname to original
    	hostnamectl hostname "$saved_hostname"
    	# Check if reverting hostname was successful
    	if [ $? -eq 0 ]; then
        	conf_msg "Hostname returned to: $saved_hostname"
    	else
        	short_msg "Failed to return hostname to: $saved_hostname."
    	fi
		# Remove backup
		rm /etc/solidcore/hostname_sc.bak
	else
    	short_msg "No hostname backup found. Skipping..."
	fi
	space_2
	space_1


	# === UNBLOCK DEVICES ===
	
	# Unblock wireless devices
	rfkill unblock all
	
	# Unblock Thunderbolt
	disabled_domains=$(boltctl list | awk '/authorized: no/ {print $1}')
	
	if [[ -z "$disabled_domains" ]]; then
	    short_msg "No Thunderbolt domains are currently disabled."
	else
	    # Re-enable each disabled domain
	    for domain in $disabled_domains; do
	        short_msg "Re-enabling Thunderbolt domain: $domain"
	        boltctl authorize "$domain"
	    done
	fi
	space_2
	space_1


	# Unmute microphone
	amixer set Capture cap
	

	# === REVERT FILE PERMISSIONS ===
	chmod -R 755 /usr/lib/modules
	chmod -R 755 /lib/modules
	


	# === UNINSTALL APPS ===
	flatpak remove flatseal
	rpm-ostree remove minisign usbguard
	rm -rf /usr/local/sbin/dnscrypt-proxy*
	conf_msg "Flatseal, minisign & USBGuard (if installed) removed"
	

	# === FIREWALL D ===
	firewall-cmd --set-default-zone public > /dev/null 2>&1
	firewall-cmd --reload > /dev/null
	conf_msg "Firewalld zone reset to default (public)"
	space_2

	# === REBOOT ===
	short_msg "Reboot required to implement all the changes."
	space_2
	read -n 1 -s -r -p ">  Press any key to continue"
    space_1
        for i in {5..1}; do
            if [ "$i" -eq 1 ]; then
                echo -ne "\r>  Rebooting in ${bold}$i${normal} second... "
            else
                echo -ne "\r>  Rebooting in ${bold}$i${normal} seconds..."
            fi
        sleep 1
        done
    echo -e "\r>  Rebooting now!            "
    reboot
else
    space_1
	short_msg "Exiting."
	space_2
	sleep 2
fi
