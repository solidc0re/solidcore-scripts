#!/bin/bash

# Solidcore first boot script
# Contains all client-side hardening settings to make porting to the image builds easier.

# === DISPLAY FUNCTIONS ===

# Non-interruptable version for short messages

short_msg() {
    local main_output=">  $1"
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
    echo -e " ${GREEN}✓${NC}"
}

# === WELCOME ===

short_msg ""
short_msg ""
short_msg "Welcome back!"
short_msg ""
short_msg "You have part-completed the solidcore hardening process."
short_msg ""
short_msg "This script carries out the finishing touches which require your input."
sleep 3
short_msg ""
short_msg ""


# === NEW PASSWORD ===

short_msg "As part of solidcore's hardening, new password policies were implemented."
sleep 1
short_msg "You are now required to set a new password. 12 characters minimum!"
short_msg "Enter it below."
passwd
short_msg ""
conf_msg "New password set"
short_msg ""
short_msg ""

# === HOSTNAME ===

# Ask the user if they want to set a new generic hostname
while true; do
read -p ">  Do you want to set a generic hostname [recommended]? Press 'n' if you already have one (y/n): " hostname_response
case $hostname_response in 
	[Yy] ) hostname_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$hostname_response" =~ ^[Yy]$ ]]; then

    # Prompt user for a new hostname
    read -r -p "Enter a new, preferably generic hostname (e.g. hostname, host, laptop...): " new_hostname

    # Temporarily change the hostname
    hostname "$new_hostname"

    # Update /etc/hostname
    echo "$new_hostname" | tee /etc/hostname > /dev/null

    # Update /etc/hosts
    sed -i "s/127.0.1.1.*/127.0.1.1\t$new_hostname/" /etc/hosts
    conf_msg "Hostname is now $new_hostname"
    short_msg ""
    short_msg ""    
else
    short_msg "Skipping..."
    short_msg ""
    short_msg ""
fi


# === MACHINE ID ===

#Whonix Machine ID
new_machine_id="b08dfa6083e7567a1921a715000001fb"

# Change machine ID in /etc/machine-id
echo "$new_machine_id" | sudo tee /etc/machine-id > /dev/null

# Change machine ID in /var/lib/dbus/machine-id
echo "$new_machine_id" | sudo tee /var/lib/dbus/machine-id > /dev/null

conf_msg "Machine IDs updated to Whonix's generic Machine ID"


# === GRUB ===

# Ask the user if they want to set a GRUB password
while true; do
read -p ">  Do you want to set a GRUB password [recommended]? (y/n): " grub_response
case $grub_response in 
	[Yy] ) grub_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

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
    conf_msg "GRUB password updated"
    short_msg ""
    short_msg ""
else
    short_msg "Skipping..."
    short_msg ""
    short_msg ""
fi


# === CUPS ===

# Enable or disable CUPS based on user response
while true; do
read -p ">  Do you use a printer? (y/n): " printer_response
case $printer_response in 
	[Yy] ) printer_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$printer_response" =~ ^[Yy]$ ]]; then
    # User confirmed using a printer
    conf_msg "Printer service (CUPS) remains enabled"
    short_msg ""
    short_msg ""
else
    # User didn't confirm using a printer, disable CUPS
    systemctl stop cups
    systemctl disable cups
    systemctl --now mask cups
    systemctl daemon-reload
    conf_msg "Printer service (CUPS) has been stopped and disabled"
    short_msg ""
    short_msg ""
fi


# === USB ===

# Install USBGuard or disable USB based on user response
while true; do
read -p ">  Do you use any USB devices? (y/n): " usb_response
case $usb_response in 
	[Yy] ) usb_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$usb_response" =~ ^[Yy]$ ]]; then
    
    rpm-ostree install usbguard > /dev/null
    script_path="/etc/solidcore/solidcore-secondboot.sh"

    # Write secondboot.sh script
    cat > "$script_path" << EOF
#!/bin/bash
        
# Solidcore second boot script

# === DISPLAY FUNCTIONS ===

# Non-interruptable version for short messages

short_msg() {
    local main_output=">  $1"
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
    echo -e " ${GREEN}✓${NC}"
}

# === WELCOME ===
        
short_msg ""
short_msg ""
short_msg "This final solidcore script finishes USBGuard setup."
sleep 3
short_msg ""
short_msg ""


# === USBGUARD ===

# Ask user to plugin all used USB devices
short_msg "USBGuard setup: plugin the USB devices you wish to whitelist.
read -n 1 -s -r -p ">  Once you've plugged them in, press any key to continue."
        
# Get USB device IDs and create whitelist rules
usbguard generate-policy > /etc/usbguard/rules.conf

# Reload usbguard service to apply the new rules
systemctl reload usbguard
systemctl enable --now usbguard.service
conf_msg "USBGuard enabled and all connected USB devices whitelisted"
sleep 1
short_msg ""
short_msg ""
short_msg "To whitelist devices in future, run:"
short_msg "$ usbguard list-devices"
short_msg ""
short_msg "Followed by:
short_msg "$ usbguard allow-device <device number>
sleep 2


# === TIDY UP & FINISH ===

rm /etc/xdg/autostart/solidcore-secondboot.desktop
short_msg ""
short_msg ""
short_msg "Thank you for running the solidcore script."
short_msg ""
short_msg "Please use the github page to report any issues and suggest improvements."
short_msg "If you encounter any issues or have any further hardening suggestions then please report them on Github."
short_msg "https://github.com/solidc0re/solidcore-scripts"
short_msg ""
short_msg "Enjoy your new hardened immutable Fedora :)"
short_msg ""
short_msg ""
sleep 2
exit 0
EOF

    chmod +x "$script_path"
    
    # Create a xdg autostart file
    cat > /etc/xdg/autostart/solidcore-firstboot.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Solidcore Script to Run on Second Boot
Exec=bash /etc/solidcore/solidcore-secondboot.sh
Terminal=true
Icon=utilities-terminal
EOF

    conf_msg "USBGuard staged for deployment on next reboot"
    short_msg ""
    short_msg ""
    
    while true; do
    
    read -p ">  Do you use any hardware security keys? (y/n): " token_response
    
    case $token_response in 
	[Yy] ) token_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
    esac
    done

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
                    conf_msg "Google Titan Security Key udev rules installed"
                    break
                    ;;
                "Yubico's YubiKey")
                    # Download and move YubiKey udev rules
                    wget https://github.com/Yubico/libfido2/raw/main/udev/70-u2f.rules
                    mv 70-u2f.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    conf_msg "Yubico's YubiKey udev rules installed"
                    break
                    ;;
                "Nitrokey")
                    # Download and move Nitrokey udev rules
                    wget https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules
                    mv 41-nitrokey.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    conf_msg "Nitrokey udev rules installed"
                    break
                    ;;
                "OnlyKey")
                    # Download and move OnlyKey udev rules
                    wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/pages/49-onlykey.rules
                    mv 49-onlykey.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    conf_msg "OnlyKey udev rules installed"
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
    conf_msg "USB has been disabled and added to the kernel module blacklist"
    short_msg ""
    short_msg ""
fi


# === WEBCAM ===

# Enable or disable the webcam based on user response

while true; do

read -p ">  If you have a non-USB connect webcam, such as an inbuilt in a laptop, do you ever use it? (y/n): " webcam_response

case $webcam_response in 
	[Yy] ) webcam_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$webcam_response" =~ ^[Yy]$ ]]; then
    conf_msg "Webcam remains enabled"
    short_msg ""
    short_msg ""
else
    rmmod uvcvideo
    echo "blacklist uvcvideo" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Webcam has been disabled and added to the kernel module blacklist"
    short_msg ""
    short_msg ""
fi


# === WIFI ===

# Enable or disable Wi-Fi based on user response

while true; do

read -p ">  Do you use Wi-Fi? (y/n): " wifi_response

case $wifi_response in 
	[Yy] ) wifi_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$wifi_response" =~ ^[Yy]$ ]]; then
    rfkill block all
    sleep 1
    rfkill unblock wifi
    conf_msg "All wireless devices, except Wi-Fi have been disabled"
    short_msg ""
    short_msg ""
else
    rfkill block all
    conf_msg "All wireless devices have been disabled"
    short_msg ""
    short_msg ""
fi


# === BLUETOOTH ===

# Enable or disable Bluetooth based on user response

while true; do

read -p ">  Do you use any Bluetooth connected devices? (y/n): " bluetooth_response

case $bluetooth_response in 
	[Yy] ) bluetooth_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$bluetooth_response" =~ ^[Yy]$ ]]; then
    rfkill unblock bluetooth
    conf_msg "Bluetooth has been re-enabled"
    short_msg ""
    short_msg ""
else
    systemctl stop bluetooth.service
    systemctl disable bluetooth.service
    systemctl --now mask bluetooth.service
    systemctl daemon-reload
    echo "blacklist bluetooth" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist btusb" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Bluetooth has been disabled and added to the kernel module blacklist"
    short_msg ""
    short_msg ""
fi

# === FIREWIRE ===

# Enable or disable Firewire based on user response

while true; do

read -p ">  Do you use any Firewire connected devices? (y/n): " firewire_response

case $firewire_response in 
	[Yy] ) firewire_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$firewire_response" =~ ^[Yy]$ ]]; then
    conf_msg "Firewire remains enabled"
    short_msg ""
    short_msg ""
else
    rmmod ohci1394 sbp2 firewire_core
    echo "blacklist firewire-core" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist ohcil394" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist sbp2" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Firewire has been disabled and added to the kernel module blacklist"
    short_msg ""
    short_msg ""
fi

# === THUNDERBOLT ===

# Enable or disable thunderbolt based on user response

while true; do

read -p ">  Do you use any Thunderbolt connected devices? (y/n): " thunderbolt_response

case $thunderbolt_response in 
	[Yy] ) thunderbolt_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'.";
esac
done

if [[ "$thunderbolt_response" =~ ^[Yy]$ ]]; then
    conf_msg "Thunderbolt remains enabled"
    short_msg ""
    short_msg ""
else
    # Get a list of active Thunderbolt domains
    active_domains=$(boltctl list | awk '/connected/ {print $1}')

    # Disable each active domain
    for domain in $active_domains; do
        echo "Disabling Thunderbolt domain: $domain"
        boltctl disable "$domain"
    done
    echo "blacklist thunderbolt" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Thunderbolt has been disabled and added to the kernel module blacklist"
    short_msg ""
    short_msg ""
fi


# === TiDY UP & FINISH ===

# Remove first boot autostart
rm /etc/exg/autostart/solidcore-firstboot.desktop

# Display notice regarding additional 
short_msg "Blacklisted kernel modules will be blacklisted on next reboot. They have been temporarily disabled until then."
short_msg ""
short_msg ""
sleep 1

# Reboot if USB Guard installed, otherwise farewell
if [[ "$usb_response" =~ ^[Yy]$ ]]; then
	short_msg "Because you confirmed you use USB devices, a final reboot is required to deploy USBGuard. Another script will guide you through whitelisting your USB devices."
	read -n 1 -s -r -p ">  Press any key to continue"
    short_msg ""
    short_msg ""
        for i in {5..1}; do
            if [ "$i" -eq 1 ]; then
                echo -ne "\r>  Rebooting in $i second... "
            else
                echo -ne "\r>  Rebooting in $i seconds..."
            fi
        sleep 1
        done
    echo -e "\r>  Rebooting now!            "
    reboot
else
    short_msg ""
    short_msg ""
    short_msg "Thank you for running the solidcore script."
	short_msg ""
    short_msg "Please use the github page to report any issues and suggest improvements."
	short_msg "If you encounter any issues or have any further hardening suggestions then please report them on Github."
    short_msg "https://github.com/solidc0re/solidcore-scripts"
	short_msg ""
    short_msg "Enjoy your new hardened immutable Fedora :)"
    short_msg ""
    short_msg ""
    sleep 2
    exit 0
fi
