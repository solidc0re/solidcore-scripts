#!/bin/bash

# Solidcore first boot script
# Contains all client-side hardening settings to make porting to the image builds easier.

# === NEW PASSWORD ===
echo "As part of solidcore's hardening, new password policies were implemented."
sleep 1
echo "You are now required to set a new password. 12 characters minimum!"
echo "Enter it below."
passwd


# === HOSTNAME ===

# Ask the user if they want to set a new generic hostname
read -p "Do you want to set a generic hostname [recommended]? Press 'n' if you already have one (Y/n): " hostname_response
if [[ "$hostname_response" =~ ^[Yy]$ ]]; then

    # Prompt user for a new hostname
    read -p "Enter a new, preferably generic hostname (e.g. hostname, host, laptop...): " new_hostname

    # Temporarily change the hostname
    hostname "$new_hostname"

    # Update /etc/hostname
    echo "$new_hostname" | tee /etc/hostname > /dev/null

    # Update /etc/hosts
    sed -i "s/127.0.1.1.*/127.0.1.1\t$new_hostname/" /etc/hosts
    echo "Hostname is now $new_hostname."
fi


# === MACHINE ID ===

#Whonix Machine ID
new_machine_id="b08dfa6083e7567a1921a715000001fb"

# Change machine ID in /etc/machine-id
echo "$new_machine_id" | sudo tee /etc/machine-id > /dev/null

# Change machine ID in /var/lib/dbus/machine-id
echo "$new_machine_id" | sudo tee /var/lib/dbus/machine-id > /dev/null

echo "Machine IDs updated to Whonix's generic Machine ID."


# === GRUB ===

# Ask the user if they want to set a GRUB password
read -p "Do you want to set a GRUB password [recommended]? (Y/n): " grub_response
if [[ "$grub_response" =~ ^[Yy]$ ]]; then
    # Generate a new GRUB password hash
    read -sp "Enter the new GRUB password: " password
    echo
    password_hash=$(echo -n "$password" | grub-mkpasswd-pbkdf2)

    # Update the GRUB configuration file
    new_entry="set superusers=\"root\"\npassword_pbkdf2 root $password_hash"
    sed -i "/^set superusers/d" /etc/grub.d/40_custom
    echo -e "$new_entry" | tee -a /etc/grub.d/40_custom > /dev/null

    # Regenerate the GRUB configuration
    grub-mkconfig -o /boot/grub/grub.cfg
    echo "GRUB password updated."
fi


# === CUPS ===

# Enable or disable CUPS based on user response
read -p "Do you use a printer? (y/N): " printer_response

if [[ "$printer_response" =~ ^[Yy]$ ]]; then
    # User confirmed using a printer
    echo "Printer service (CUPS) remains enabled."
else
    # User didn't confirm using a printer, disable CUPS
    systemctl stop cups
    systemctl disable cups
    systemctl --now mask cups
    systemctl daemon-reload
    echo "Printer service (CUPS) has been stopped and disabled."
fi


# === USB ===

# Install USBGuard or disable USB based on user response
read -p "Do you use any USB devices? (Y/n): " usb_response

if [[ "$usb_response" =~ ^[Yy]$ ]]; then
    
    rpm-ostree install usbguard
    script_path="/etc/solidcore/solidcore-secondboot.sh"

    # Write secondboot.sh script
    cat > "$script_path" << EOF
        #!/bin/bash
        
        # Solidcore second boot script
        # Ask user to plugin all used USB devices
        echo "USBGuard setup: plugin the USB devices you wish to whitelist. Once you've plugged them in, press any key to continue.
        read -s -n 1 -p ""
        
        # Get USB device IDs and create whitelist rules
        usbguard generate-policy > /etc/usbguard/rules.conf
        echo "Whitelist rules generated and saved to /etc/usbguard/rules.conf."

        # Reload usbguard service to apply the new rules
        systemctl reload usbguard
        systemctl enable --now usbguard.service
        echo "USBGuard enabled."
        systemctl disable solidcore-second-boot.service
        rm /etc/systemd/system/solidcore-second-boot.service
        systemctl daemon-reload
        echo "Thank you for running the solidcore script."
		echo "Please use the github page to report any issues and suggest improvements."
		echo "link"
		echo "Enjoy your new hardened immutable Fedora :)"
	EOF
    chmod +x "$script_path"

    # Create a systemd service unit
    service_unit_file="/etc/systemd/system/solidcore-second-boot.service"
    cat > "$service_unit_file" << EOF
   		[Unit]
    	Description=Solidcore Script to Run on Second Boot

    	[Service]
    	Type=oneshot
    	ExecStart=sudo $script_path

    	[Install]
    	WantedBy=multi-user.target
	EOF

    # Make the service unit file readable only by root
    chmod 600 "$service_unit_file"

    # Enable and start the service
    systemctl enable solidcore-second-boot.service
    systemctl start solidcore-second-boot.service
    echo "USBGuard staged for deployment on next reboot."
    
    read -p "Do you use any hardware security keys? (y/N): " token_response
    if [[ "$token_response" =~ ^[Yy]$ ]]; then
        # User prompt for security key type
        PS3="Select your preferred security key type: "
        options=("Google Titan Security Key" "Yubico's YubiKey" "Nitrokey" "OnlyKey" "Other")
        select opt in "${options[@]}"
        do
            case $opt in
                "Google Titan Security Key")
                    # Define the rule content
                    RULE_CONTENT='KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="18d1|096e", ATTRS{idProduct}=="5026|0858|085b", TAG+="uaccess"'

                    # Create the udev rules file and add the rule content
                    echo "$RULE_CONTENT" | tee /etc/udev/rules.d/70-titan-key.rules > /dev/null
                    udevadm control --reload-rules && udevadm trigger
                    echo "Google Titan Security Key udev rules installed."
                    break
                    ;;
                "Yubico's YubiKey")
                    # Download and move YubiKey udev rules
                    wget https://github.com/Yubico/libfido2/raw/main/udev/70-u2f.rules
                    mv 70-u2f.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    echo "Yubico's YubiKey udev rules installed."
                    break
                    ;;
                "Nitrokey")
                    # Download and move Nitrokey udev rules
                    wget https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules
                    mv 41-nitrokey.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    echo "Nitrokey udev rules installed."
                    break
                    ;;
                "OnlyKey")
                    # Download and move OnlyKey udev rules
                    wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/pages/49-onlykey.rules
                    mv 49-onlykey.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    echo "OnlyKey udev rules installed."
                    break
                    ;;
                "Other")
                    echo "Other hardware tokens are not currently supported by this script."
                    echo "Please check with your hardware security key supplier for instructions on how to implement the required udev rules."
                    sleep 3
                    break
                    ;;
                *) echo "Invalid option";;
            esac
        done
    fi

else
    rmmod usbcore usb_storage
    blacklist_file="/etc/modprobe.d/solidcore-blacklist.conf"
    echo "blacklist usb_storage" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist usbcore" | tee -a "$blacklist_file" > /dev/null
    echo "USB has been disabled and added to the kernel module blacklist."
fi


# === WEBCAM ===

# Enable or disable the webcam based on user response
read -p "If you have a non-USB connect webcame, such as an inbuilt one in your monitor, do you ever use it? (Y/n): " webcam_response

if [[ "$webcam_response" =~ ^[Yy]$ ]]; then
    echo "Webcam remains enabled."
else
    rmmod uvcvideo
    echo "blacklist uvcvideo" | tee -a "$blacklist_file" > /dev/null
    echo "Webcam has been disabled and added to the kernel module blacklist."
fi


# === WIFI ===

# Enable or disable Wi-Fi based on user response
read -p "Do you use Wi-Fi? (Y/n): " wifi_response

if [[ "$wifi_response" =~ ^[Yy]$ ]]; then
    rfkill block all
    sleep 1
    rfkill unblock wifi
    echo "All wireless devices, except Wi-Fi have been disabled."
else
    rfkill block all
    echo "All wireless devices have been disabled."
fi


# === BLUETOOTH ===

# Enable or disable Bluetooth based on user response
read -p "Do you use any Bluetooth connected devices? (y/N): " bluetooth_response

if [[ "$bluetooth_response" =~ ^[Yy]$ ]]; then
    rfkill unblock bluetooth
    echo "Bluetooth has been re-enabled."
else
    systemctl stop bluetooth.service
    systemctl disable bluetooth.service
    systemctl --now mask bluetooth.service
    systemctl daemon-reload
    echo "blacklist bluetooth" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist btusb" | tee -a "$blacklist_file" > /dev/null
    echo "Bluetooth has been disabled and added to the kernel module blacklist."
fi

# === FIREWIRE ===

# Enable or disable Firewire based on user response
read -p "Do you use any Firewire connected devices? (y/N): " firewire_response

if [[ "$firewire_response" =~ ^[Yy]$ ]]; then
    echo "Firewire remains enabled."
else
    rmmod ohci1394 sbp2 firewire_core
    echo "blacklist firewire-core" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist ohcil394" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist sbp2" | tee -a "$blacklist_file" > /dev/null
    echo "Firewire has been disabled and added to the kernel module blacklist."
fi

# === THUNDERBOLT ===

# Enable or disable thunderbolt based on user response
read -p "Do you use any Thunderbolt connected devices? (y/N): " thunderbolt_response

if [[ "$thunderbolt_response" =~ ^[Yy]$ ]]; then
    echo "Thunderbolt remains enabled."
else
    # Get a list of active Thunderbolt domains
    active_domains=$(boltctl list | awk '/connected/ {print $1}')

    # Disable each active domain
    for domain in $active_domains; do
        echo "Disabling Thunderbolt domain: $domain"
        boltctl disable "$domain"
    done
    echo "blacklist thunderbolt" | tee -a "$blacklist_file" > /dev/null
    echo "Thunderbolt has been disabled and added to the kernel module blacklist."
fi


# === END FIRST BOOT SERVICE ===

# Disable and remove first boot service
systemctl disable solidcore-first-boot.service
rm /etc/systemd/system/solidcore-first-boot.service
systemctl daemon-reload

# Display notice regarding additional 
echo "Blacklisted kernel modules will be blacklisted on next reboot. They have been temporarily disabled until then."
sleep 1
echo
if [[ "$usb_response" =~ ^[Yy]$ ]]; then
	echo "Because you confirmed you use USB devices, a final reboot is required to deploy USBGuard. Another script will guide you through whitelisting your USB devices."
	sleep 1
	for i in {5..1}; do
    	echo -ne "\rRebooting in $i seconds..."
    	sleep 1
	done
	echo -e "\rRebooting now!"
	reboot
else
	echo "Thank you for running the solidcore script."
	echo "Please use the github page to report any issues and suggest improvements."
	echo "link"
	echo "Enjoy your new hardened immutable Fedora :)"
fi
exit 0
