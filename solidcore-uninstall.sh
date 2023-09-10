#!/bin/bash

## Solidcore Hardening Scripts for Fedora's rpm-ostree Operating Systems
## Version 0.2.7
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

# Running order
# - Display functions
# - Flags
# - Sudo check
# - Inform user they are about to uninstall (y/n), if yes...
# - Undo rpm-ostree kargs
# - Restore backup files
# - Unmask masked serviecs
# - Delete install services
# - Delete installed files and configurations
# - Restore sysctl defaults
# - Restore Fedora flatpaks
# - Revert password policies
# - Revert hostname
# - Uninstall flatseal, minisign, USBGuard and dnscrypt-proxy
# - Return Firewalld to previous default
# - Create farewell and uninstall2 scripts to run on reboot (re-enables bluetooth, re-inserts removed modules [is this needed?], unblocks Thunderbolt domains and wireless devices, unmutes microphone)
# - Reboot


# === DISPLAY FUNCTIONS ===

# Declare bold and normal
bold=$(tput bold)
green=$(tput setaf 2)
italics=$(tput sitm)
normal=$(tput sgr0)

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
conf_msg() {
    short_msg "$1"
    echo -ne " ${bold}${green}✓${normal}"
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

# === FLAGS ===

# Test mode
# Check if the -test flag is provided
if [[ "$1" == "-test" ]]; then
    test_mode=true
    short_msg "Test mode."
else
    test_mode=false
fi


# === SUDO CHECK ===
if [ "$EUID" -ne 0 ]; then
    short_msg "This script requires sudo privileges. Please run it with 'sudo' using 'sudo <path-to-script>./solidcore-uninstall.sh"
    exit 1
fi


# === INFORM USER ===
clear
space_2
short_msg "You are about to uninstall all solidcore changes to your system."
space_1
while true; do
read -rp "${bold}Question: Do you want to continue?${normal} (y/n): " uninstall_response
case $uninstall_response in
	[Yy] ) uninstall_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        space_1;
esac
done
space_2

if [[ "$uninstall_response" =~ ^[Yy]$ ]]; then


	# === RESTORE BOOT PARAMETERS ===
	# Add all added parameters to kargs_added string
	kargs_added=""
	while IFS= read -r line; do
    	kargs_added+="--delete-if-present=$line "
	done < /etc/solidcore/kargs-added_sc.bak

	# Remove the trailing space
	kargs_added="${kargs_added%" "}"

	# Remove all added parameters saved in kargs-added_sc.bak
	rpm-ostree cancel -q
	rpm-ostree kargs -q "$kargs_added"
	conf_msg "solidcore added boot parameters removed"

	# Add all original parameters to kargs_orig string
	kargs_orig=""
	while IFS= read -r line; do
    	kargs_orig+="--append-if-missing=$line "
	done < /etc/solidcore/kargs-orig_sc.bak

	# Remove the trailing space
	kargs_orig="${kargs_orig%" "}"

	# Append all added parameters saved in kargs-orig_sc.bak
	rpm-ostree cancel -q
	rpm-ostree kargs -q "$kargs_orig"
	conf_msg "Original boot parameters restored"


	# === RESTORE BACKUPS ===
	
	# Define an array of files to be restored
	files_to_restore=(
	    "/etc/chrony.conf"
		"/etc/default/grub"
    	"/etc/fstab"
		"/etc/machine-id"
		"/etc/resolv.conf"
 	    "/etc/rpm-ostreed.conf"
		"/etc/security/access.conf"
		"/etc/security/faillock.conf"
    	"/etc/security/limits.conf"
		"/etc/security/pwquality.conf"
    	"/etc/ssh/sshd_config"
		"/etc/sysconfig/chronyd"
    	"/etc/systemd/coredump.conf"
    	"/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf"
		"/etc/xdg/autostart/org.gnome.Software.desktop"
	    "/var/lib/dbus/machine-id"
	)

	# Loop through the array and restore backup copies
	for source_file in "${files_to_restore[@]}"; do
    	# Check if the backup file exists
    	backup_file="${source_file}_sc.bak"
    	if [ -e "$backup_file" ]; then
    	    if [ "$backup_file" == "/var/lib/dbus/machine-id" ]; then
				# Restore the backup file
    	    	cp -f "$backup_file" "$source_file"
    	    	conf_msg "Backup restored for: $source_file"
    	    	# Remove the backup file
    	    	rm "$backup_file"
    	    	conf_msg "Machine ID restored"
			else	
				# Restore the backup file
    	    	cp -f "$backup_file" "$source_file"
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

	# Run update-grub to update GRUB configuration
	if grub2-mkconfig -o /boot/grub2/grub.cfg; then
    	conf_msg "GRUB configuration updated"
	else
    	short_msg "Failed to update GRUB configuration."
	fi


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
    	# Unmake the service/socket
    	systemctl unmask "$service"
    	# Echo a message
    	conf_msg "$service unmasked"
	done

	# Stop dnscrypt-proxy
	/usr/local/sbin/dnscrypt-proxy/dnscrypt-proxy -service stop

	# Restart systemd-resolved
	systemctl enable --now systemd-resolved


	# === REMOVE SOLIDCORE SERVICES ===

	services_to_delete=(
		"dnscrypt-proxy-update.service"
		"dnscrypt-proxy-update.timer"
		"flatpak-update.service"
		"flatpak-update.timer"
		"solidcore-remount.service"
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

	# === REMOVE SOLICORE CREATED SCRIPTS & CONFIGS ===

	files_to_delete=(
		"/etc/modprobe.d/solidcore-blocklist.conf"
		"/etc/NetworkManager/conf.d/00-solidcore.conf"
		"/etc/profile.d/solidcore_umask.sh"
		"/etc/solidcore/kargs-orig_sc.bak"
		"/etc/solidcore/kargs-added_sc.bak"
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
	)

	for file in "${files_to_delete[@]}"; do
	    # Check if the source file exists
	    if [ -e "$file" ]; then
	    # Delete file
	    rm "$file"
		systemctl daemon-reload
	    conf_msg "Solidcore created file removed: $file"
		fi
	done


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

     # === RESTORE FEDORA FLATPAKs ===

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


	# === REVERT PASSWORD POLICIES ===
	
	authselect select sssd
	conf_msg "Default password policies applied"
	
	rm -rf /etc/authselect/custom/solidcore*
	conf_msg "Solidcore password policies removed"

	passwd -u root
	conf_msg "root account unlocked"
	

	# === REVERT HOSTNAME ===
	# Check if the file exists
	if [ -f "/etc/solidcore/hostname_sc.bak" ]; then
    	# Read the hostname from backup
    	saved_hostname=$(cat "/etc/solidcore/hostname_sc.bak")
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


	# === UNINSTALL APPS ===
	flatpak remove flatseal > /dev/null 2>&1
	rpm-ostree cancel -q
	rpm-ostree remove -q minisign usbguard > /dev/null 2>&1
	rm -rf /usr/local/sbin/dnscrypt-proxy* > /dev/null 2>&1
	conf_msg "DNSCrypt-Proxy, Flatseal, minisign & USBGuard (if installed) removed"
	

	# === FIREWALL D ===
	firewall-cmd --set-default-zone public > /dev/null 2>&1
	firewall-cmd --reload > /dev/null
	conf_msg "Firewalld zone reset to default (public)"

	# === AFTER REBOOT ===
	# Create farewell script
cat > /etc/solidcore/solidcore-farewell.sh << EOF
#!/bin/bash
## Solidcore Hardening Scripts for Fedora's rpm-ostree Operating Systems
## Version 0.2.7
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

# Farewell script


# === RUN UNINSTALL PART DEUX ===
clear
echo ">"
echo ">"
echo "> Please enter your sudo password to carry out the final parts of the solidcore uninstall process."
sudo bash /etc/solidcore/solidcore-uninstall2.sh
EOF

	# Make executable
	chmod +x /etc/solidcore/solidcore-farewell.sh

	# Create a xdg autostart file
cat > /etc/xdg/autostart/solidcore-farewell.desktop << EOF
[Desktop Entry]
Type=Application
Name=Solidcore Script to Run on First Boot
Exec=/etc/solidcore/solidcore-farewell.sh
Terminal=true
Icon=utilities-terminal
EOF

	# Write uninstall2.sh script
cat > /etc/solidcore/solidcore-uninstall2.sh << EOF
#!/bin/bash
        
## Solidcore Hardening Scripts for Fedora's rpm-ostree Operating Systems
## Version 0.2.7
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

# Uninstall part deux script


# === DISPLAY FUNCTIONS ===

# Declare bold and normal
bold=$(tput bold)
green=$(tput setaf 2)
italics=$(tput sitm)
normal=$(tput sgr0)

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
conf_msg() {
    short_msg "$1"
    echo -ne " ${bold}${green}✓${normal}"
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


# === WELCOME ===
        
space_2
short_msg "Initiating final uninstall process..."
sleep 3
space_2


# === RE-ENABLE DEVICES & PORTS ===

# Re-enable services
services=(
	bluetooth.service
)

# Loop through the array and unmask
for service in "${services[@]}"; do
   	# Unmask the service/socket
   	systemctl unmask "$service"
	systemctl enable --now "$service"
   	# Echo a message
   	conf_msg "$service unmasked"
done
systemctl daemon-reload

# Re-insert bluetooth, Firewire, USB & webcam modules
modprobe bluetooth btusb dv1394 firewire-core firewire_core firewire-ohci firewire_ohci firewire-sbp2 firewire_sbp2 ohci1394 sbp2 raw1394 video1394 usbcore usb_storage uvcvideo

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

# Unblock wireless devices
rfkill unblock all

# Unmute microphone
amixer set Capture cap	


# === TIDY UP & FINISH ===

rm -rf /etc/xdg/autostart/solidcore-farewell.desktop > /dev/null 2>&1
rm -rf /etc/solidcore* > /dev/null 2>&1
conf_msg "Removed uninstall files"
space_2
short_msg "${bold}Thank you for using the solidcore script.${normal}"
sleep 2
echo
EOF

    chmod +x /etc/solidcore/solidcore-uninstall2.sh

	conf_msg "Set up next boot script to finish uninstall process"
	

	# === REBOOT ===
	short_msg "${bold}Reboot required to implement all the changes.${normal}"
	space_2
	read -n 1 -s -r -p "Press any key to continue..."
	# remove uninstall script
	rm -rf /etc/solidcore/solidcore-uninstall.sh
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
