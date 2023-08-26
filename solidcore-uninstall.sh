#!/bin/bash

# Solidcore uninstall file

# === SUDO CHECK ===
# Check if the script is being run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script requires sudo privileges. Please run it with 'sudo' using 'sudo <path-to-script>./solidcore-uninstall.sh"
    exit 1
fi


# === INFORM USER ===
echo "You are about to uninstall all solidcore changes to your system."
read -p "Do you want to continue (Y/n): " uninstall_response

if [[ "$uninstall_response" =~ ^[Yy]$ ]]; then

	# === RESTORE BACKUPS ===
	
	# Define an array of files to be restored
	files_to_restore=(
	    "/etc/default/grub"
    	    "/etc/fstab"
 	    "/etc/rpm-ostreed.conf"
    	    "/etc/security/limits.conf"
    	    "/etc/ssh/sshd_config"
    	    "/etc/systemd/coredump.conf"
    	    "/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf"
    	    "/etc/systemd/system/systemd-logind.service.d/hidepid.conf"
	)

	# Loop through the array and restore backup copies
	for source_file in "${files_to_restore[@]}"; do
    	# Check if the backup file exists
    	backup_file="${source_file}_sc.bak"
    	if [ -e "$backup_file" ]; then
    	    # Restore the backup file
    	    cp "$backup_file" "$source_file"
    	    echo "Backup restored for: $source_file"
    	    # Remove the backup file
    	    rm "$backup_file"
    	    echo "Backup removed: $backup_file"
    	else
    	    echo "Backup file '$backup_file' does not exist."
	    # Check if the source file exists
    	    if [ -e "$source_file" ]; then
    	        # Check if the source file should be deleted
    	        case "$source_file" in
    	            *"/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf"*)
    	                # Delete the source file
    	                rm -f "$source_file"
    	                echo "Deleted: $source_file"
    	                ;;
    	            *"/etc/systemd/system/systemd-logind.service.d/hidepid.conf"*)
    	                # Delete the source file
    	                rm -f "$source_file"
    	                echo "Deleted: $source_file"
    	                ;;
    	            *)
    	                echo "No action needed for: $source_file"
    	                ;;
    	        esac
    	    fi
    	fi
	done

	# Run update-grub to update GRUB configuration
	if grub2-mkconfig -o /boot/grub2/grub.cfg; then
    	echo "GRUB configuration updated."
	else
    	echo "Failed to update GRUB configuration."
	fi

	# Update initramfs after removing kernel module blacklist file
	dracut --regenerate-all

	# === UNMASK SERVICES ===
	services=(
    	avahi-daemon
    	cups
    	httpd
    	nfs-server
    	rpcbind
    	rpm-ostree-countme.service
    	sshd
	)

	# Loop through the array and unmask
	for service in "${services[@]}"; do
    	# Stop the service/socket
    	systemctl unmask "$service"
    	# Echo a message
    	echo "$service unmasked."
	done


	# === REMOVE SOLIDCORE SYSCTL SERVICES ===

	services_to_delete=(
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
	    # Echo a message
	    echo "$service disabled and deleted."
	done

	# === REMOVE SOLICORE CREATED SCRIPTS & CONFIGS ===

	files_to_delete=(
		"/etc/modprobe.d/solidcore-blacklist.conf"
		"/etc/profile.d/solidcore_umask.sh"
		"/etc/solidcore/firstboot.sh"
		"/etc/solidcore/secondboot.sh"
		"/etc/udev/rules.d/70-titan-key.rules"
		"/etc/udev/rules.d/70-u2f.rules"
		"/etc/udev/rules.d/41-nitrokey.rules"
		"/etc/udev/rules.d/49-onlykey.rules"
	)

	for file in "${files_to_delete[@]}"; do
	    # Check if the source file exists
	    if [ -e "$file" ]; then
	    # Delete file
	    rm "$file"
	    echo "Solidcore created file removed: $override_file"
		fi
	done

	# === RESTORE SYSCTL SETTINGS ===

	# Check if the script exists
	if [ -e "/etc/solidcore/defaults.sh" ]; then
	    # Run the script
	    /etc/solidcore/defaults.sh
	    echo "Sysctl settings restored."
	    # Reload sysctmctl
	    systemctl daemon-reload
	    # Remove old stored settings
	    rm /etc/solidcore/defaults.sh
	else
	    echo "Script /etc/solidcore/defaults.sh does not exist."
	fi


        # === RESTORE FEDORA FLATPAK ===

 	# Check if the script exists
	if [ -e "/etc/solidcore/fedora_flatpak.sh" ]; then
	    # Run the script
	    /etc/solidcore/fedora_flatpak.sh
	    echo "Fedora Flatpaks restored."
	    # Remove flatpak undo script
	    rm /etc/solidcore/fedora_flatpak.sh
	else
	    echo "Script /etc/solidcore/fedora_flatpak.sh does not exist."
	fi


	# === REVERT PASSWORD POLICIES ===

	update-crypto-policies --set DEFAULT
	echo "Default cryptographic policies applied."
	
	authselect select sssd
	echo "Default password policies applied."
	
	passwd -u root
	echo "root account unlocked."
	
	# === UNBLOCK DEVICES ===
	
	# Unblock wireless devices
	rfkill unblock all
	
	# Unblock Thunderbolt
	disabled_domains=$(boltctl list | awk '/authorized: no/ {print $1}')
	
	if [[ -z "$disabled_domains" ]]; then
	    echo "No Thunderbolt domains are currently disabled."
	else
	    # Re-enable each disabled domain
	    for domain in $disabled_domains; do
	        echo "Re-enabling Thunderbolt domain: $domain"
	        boltctl authorize "$domain"
	    done
	fi
	
	# Unmute microphone
	amixer set Capture cap
	
	# === REVERT FILE PERMISSIONS ===
	chmod -R 755 /usr/lib/modules
	chmod -R 755 /lib/modules
	
	# === UNINSTALL APPS ===
	flatpak remove flatseal
	rpm-ostree remove dnscrypt-proxy usbguard
	echo "Flatseal & dnscrypt-proxy removed."
	
	
	# === REBOOT ===
	echo "Reboot required to implement all the changes."
	sleep 1
	for i in {5..1}; do
	    echo -ne "\rRebooting in $i seconds..."
	    sleep 1
	done
	echo -e "\rRebooting now!"
	reboot
else
    echo "Exiting."
fi
