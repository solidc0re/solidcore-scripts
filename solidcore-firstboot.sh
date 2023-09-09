#!/bin/bash

## Solidcore Hardening Scripts for Fedora's rpm-ostree Operating Systems
## Version 0.1.1
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

# First boot script


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
GREEN='\033[0;32m'
NC='\033[0m' # No Color

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


# === VARIABLES ===
blacklist_file="/etc/modprobe.d/solidcore-blacklist.conf"


# === WELCOME ===

clear
long_msg ">
>
>  Welcome back!
>
>  You have part-completed the solidcore hardening process.
>
>  This script carries out the finishing touches which require your input."
sleep 2
space_2


# === SUDO CHECK ===

if [ "$EUID" -ne 0 ]; then
    short_msg "This script requires sudo privileges. Please run it with 'sudo' using 'sudo <path-to-script>./solidcore-firstboot.sh'"
    exit 1
fi


# === NEW PASSWORD ===

short_msg "As part of solidcore's hardening, new password policies were implemented."
sleep 1
space_1
while true; do
    short_msg "${bold}You are now required to set a new password.${normal}"
    sleep 1
    space_1
    short_msg "The new password requirements are:"
    short_msg "  • 12 character minimum"
    short_msg "  • at least 1 UPPER case character"
    short_msg "  • at least 1 lower case character"
    short_msg "  • the same character can not be repeated 3+ times in a row"
    short_msg "  • the password must pass a dictionary test"
    space_1
    short_msg "Numbers and special characters are permitted, but not required."
    space_1
    short_msg "${bold}Password length is more important than complexity.${normal}"
    space_1
    short_msg "For example, ${italics}TwoClownsWalkedintoaBar${normal} is better than ${italics}dVc78#!_sjdRa${normal}."
    sleep 1
    space_1
    short_msg "Enter your new password below."
    space_1
    echo
    passwd > /dev/null
    if [ $? -eq 0 ]; then
        space_1
        conf_msg "New password set"
        break
    else
        space_1
        short_msg "Password change failed. Please try again."
        space_1
        short_msg "A reminder that the new password requirements are:"
        short_msg "  • 12 character minimum"
        short_msg "  • at least 1 UPPER case character"
        short_msg "  • at least 1 lower case character"
        short_msg "  • the same character can not be repeated 3+ times in a row"
        short_msg "  • the password must pass a dictionary test"
        space_1
    fi
done
conf_msg "Password updated"

# Expire passwords of all other users
short_msg "Expiring all user passwords except for user..."


# Count the number of non-root users on the system
num_users=$(getent passwd | grep -v '/bin/false' | grep -v '/sbin/nologin' | wc -l)

# Check if there are other users besides the current user and root
if [ "$num_users" -gt 2 ]; then
    # Loop through all user accounts and exclude the current user and root
    for username in $(getent passwd | cut -d: -f1); do
        if [ "$username" != "$current_user" ] && [ "$username" != "root" ]; then
            echo "Expiring password for user: $username"
            chage -E 0 "$username"
        fi
    done
    space_1
    short_msg "${bold}All other users' passwords have now expired${normal}."
    short_msg "They will be prompted to update their password on the next login."
    sleep 1

fi

space_2
space_1

# === HOSTNAME ===

# Ask the user if they want to set a new generic hostname
while true; do
read -rp "${bold}Question: Do you want to set a generic hostname [recommended]?${normal}`echo $'\n>  Examples include 'hostname', 'host', 'computer', etc. (y/n) :  '`" hostname_response
case $hostname_response in 
	[Yy] ) hostname_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done
space_2

if [[ "$hostname_response" =~ ^[Yy]$ ]]; then
    # Create backup
    echo hostnamectl hostname > /etc/solidcore/hostname_sc.bak
    # Prompt user for a new hostname
    read -r -p "Enter new hostname: " new_hostname
    # Update hostname
    hostnamectl hostname "$new_hostname" 
    conf_msg "Hostname is now $new_hostname"
else
    short_msg "Skipping..."
fi
space_2
space_1

# === GRUB ===

# Ask the user if they want to set a GRUB password
short_msg "Setting a GRUB password prevents an attacker from accessing the bootloader configuration menus and terminal."
space_1
while true; do
read -rp "${bold}Question: Do you want to set a GRUB password [recommended]?${normal} (y/n): " grub_response
case $grub_response in 
	[Yy] ) grub_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$grub_response" =~ ^[Yy]$ ]]; then
    # Set new GRUB password
    while true; do
        echo
        grub2-setpassword
        if [ $? -eq 0 ]; then
            space_1
            conf_msg "New password set"
            break
        else
            space_1
            short_msg "Password change failed. Please try again."
        fi
    done
else
    short_msg "Skipping..."
fi

space_2
space_1


# === CUPS ===

# Enable or disable CUPS based on user response
while true; do
read -rp "${bold}Question: Do you use a printer?${normal} (y/n): " printer_response
case $printer_response in 
	[Yy] ) printer_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$printer_response" =~ ^[Yy]$ ]]; then
    # User confirmed using a printer
    conf_msg "Printer service (CUPS) remains enabled"
else
    # User didn't confirm using a printer, disable CUPS
    systemctl stop cups
    systemctl disable cups > /dev/null 2>&1
    systemctl --now mask cups > /dev/null 2>&1
    systemctl daemon-reload
    space_1
    conf_msg "Printer service (CUPS) has been stopped and disabled"
fi
space_2
space_1

# === USB ===

# Install USBGuard or disable USB based on user response
while true; do
read -rp "${bold}Question: Do you use any USB devices?${normal} (y/n): " usb_response
case $usb_response in 
	[Yy] ) usb_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$usb_response" =~ ^[Yy]$ ]]; then
    if rpm -q usbguard > /dev/null 2>&1; then
        # Cancel USB-enabled reboot sequence by setting usb_response to N
        usb_response="N"
        short_msg "USBGuard already installed. Skipping..."
    else
        space_1
        short_msg "Installing USBGaurd. This may take a while."
        echo
        rpm-ostree install usbguard
        script_path="/etc/solidcore/solidcore-secondboot.sh"

        # Write secondboot.sh script
cat > "$script_path" << EOF
#!/bin/bash
        
## Solidcore Hardening Scripts for Fedora's rpm-ostree Operating Systems
## Version 0.1.1
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

# Second boot script


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
GREEN='\033[0;32m'
NC='\033[0m' # No Color

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
short_msg "This final solidcore script finishes USBGuard setup."
sleep 3
space_2


# === USBGUARD ===

# Ask user to plugin all used USB devices
short_msg "${bold}USBGuard setup: plugin the USB devices you wish to whitelist.${normal}"
read -n 1 -s -r -p "  Once you've plugged them in, press any key to continue."
        
# Get USB device IDs and create whitelist rules
sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'

# Increase hardening and privacy of USBGuard
# usbguard set-parameter PresentControllerPolicy=apply-policy
# usbguard set-parameter HidePII=true

# Reload usbguard service to apply the new rules
systemctl enable --now usbguard.service > /dev/null
conf_msg "USBGuard enabled and all connected USB devices whitelisted"
sleep 2
space_2
short_msg "To whitelist devices in future, run:"
space_1
short_msg "$ usbguard list-devices"
space_1
short_msg "Followed by:
space_1
short_msg "$ usbguard allow-device <device number>
sleep 2


# === TIDY UP & FINISH ===

rm /etc/xdg/autostart/solidcore-welcome.desktop > /dev/null 2>&1
space_2
short_msg "${bold}Thank you for running the solidcore script.${normal}"
space_1
short_msg "For some suggestions on what to do next, see:"
short_msg "https://github.com/solidc0re/solidcore-scripts#post-install-information"
space_1
short_msg "Enjoy your new hardened immutable Fedora :)"
space_2
sleep 2
echo
EOF

        chmod +x "$script_path"
    
        # Update solidcore-welcome.sh to run secondboot script
        sed -i 's|firstboot.sh|secondboot.sh|' /etc/solidcore/solidcore-welcome.sh
        space_1
        conf_msg "USBGuard staged for deployment on next reboot"
        space_2
        space_1
    fi
    
    while true; do
    
    read -rp "${bold}Question: Do you use any hardware security keys?${normal} (y/n): " token_response
    
    case $token_response in 
	[Yy] ) token_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
    esac
    done

    if [[ "$token_response" =~ ^[Yy]$ ]]; then
        # User prompt for security key type
        PS3="Select your security key type: "
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
                    space_1
                    conf_msg "Google Titan Security Key udev rules installed"
                    break
                    ;;
                "Yubico's YubiKey")
                    # Download and move YubiKey udev rules
                    wget https://github.com/Yubico/libfido2/raw/main/udev/70-u2f.rules
                    mv 70-u2f.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    space_1
                    conf_msg "Yubico's YubiKey udev rules installed"
                    break
                    ;;
                "Nitrokey")
                    # Download and move Nitrokey udev rules
                    wget https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules
                    mv 41-nitrokey.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    space_1
                    conf_msg "Nitrokey udev rules installed"
                    break
                    ;;
                "OnlyKey")
                    # Download and move OnlyKey udev rules
                    wget https://raw.githubusercontent.com/trustcrypto/trustcrypto.github.io/pages/49-onlykey.rules
                    mv 49-onlykey.rules /etc/udev/rules.d/
                    udevadm control --reload-rules && udevadm trigger
                    space_1
                    conf_msg "OnlyKey udev rules installed"
                    break
                    ;;
                "Other")
                    space_1
                    short_msg "Other hardware tokens are not currently supported by this script."
                    short_msg "Please check with your hardware security key supplier for instructions on how to implement the required udev rules."
                    sleep 3
                    break
                    ;;
                *) echo "Invalid option";;
            esac
        done
    fi

else
    rmmod usbcore usb_storage > /dev/null 2>&1
    echo "install usb_storage /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install usbcore /bin/true" | tee -a "$blacklist_file" > /dev/null
    space_1
    conf_msg "USB has been disabled and added to the kernel module blacklist"
fi

space_2
space_1

# === WEBCAM ===

# Enable or disable the webcam based on user response

while true; do

read -rp "${bold}Question: If you have a non-USB connect webcam, such as an in-built one in a laptop, do you use it?${normal} (y/n): " webcam_response

case $webcam_response in 
	[Yy] ) webcam_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$webcam_response" =~ ^[Yy]$ ]]; then
    space_1
    conf_msg "Webcam remains enabled"
else
    rmmod uvcvideo > /dev/null 2>&1
    echo "install uvcvideo /bin/true" | tee -a "$blacklist_file" > /dev/null
    space_1
    conf_msg "Webcam has been disabled and added to the kernel module blacklist"
fi

space_2
space_1


# === WIFI ===

# Enable or disable Wi-Fi based on user response

while true; do

read -rp "${bold}Question: Do you use Wi-Fi?${normal} (y/n): " wifi_response

case $wifi_response in 
	[Yy] ) wifi_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$wifi_response" =~ ^[Yy]$ ]]; then
    rfkill block all
    sleep 1
    rfkill unblock wifi
    space_1
    conf_msg "All wireless devices, except Wi-Fi have been disabled"
else
    rfkill block all
    space_1
    conf_msg "All wireless devices have been disabled"
fi

space_2
space_1


# === BLUETOOTH ===

# Enable or disable Bluetooth based on user response

while true; do

read -rp "${bold}Question: Do you use any Bluetooth connected devices?${normal} (y/n): " bluetooth_response

case $bluetooth_response in 
	[Yy] ) bluetooth_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$bluetooth_response" =~ ^[Yy]$ ]]; then
    rfkill unblock bluetooth
    space_1
    conf_msg "Bluetooth has been re-enabled"
else
    systemctl stop bluetooth.service
    systemctl disable bluetooth.service > /dev/null 2>&1
    systemctl --now mask bluetooth.service > /dev/null 2>&1
    systemctl daemon-reload
    echo "install bluetooth /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install btusb /bin/true" | tee -a "$blacklist_file" > /dev/null
    space_1
    conf_msg "Bluetooth has been disabled and added to the kernel module blacklist"
fi

space_2
space_1


# === FIREWIRE ===

# Enable or disable Firewire based on user response

while true; do

read -rp "${bold}Question: Do you use any Firewire connected devices?${normal} (y/n): " firewire_response

case $firewire_response in 
	[Yy] ) firewire_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$firewire_response" =~ ^[Yy]$ ]]; then
    space_1
    conf_msg "Firewire remains enabled"
else
    rmmod dv1394 firewire-core firewire_core firewire-ohci firewire_ohci firewire-sbp2 firewire_sbp2 ohci1394 sbp2 raw1394 video1394 > /dev/null 2>&1
    echo "install dv1394 /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire-core /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire_core /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire-ohci /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire_ohci /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire-sbp2 /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire_sbp2 /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install firewire-core /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install ohci1394 /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install sbp2 /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install raw1394 /bin/true" | tee -a "$blacklist_file" > /dev/null
    echo "install video1394 /bin/true" | tee -a "$blacklist_file" > /dev/null
    space_1
    conf_msg "Firewire has been disabled and added to the kernel module blacklist"
fi

space_2
space_1


# === THUNDERBOLT ===

# Enable or disable thunderbolt based on user response

while true; do

read -rp "${bold}Question: Do you use any Thunderbolt connected devices?${normal} (y/n): " thunderbolt_response

case $thunderbolt_response in 
	[Yy] ) thunderbolt_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

if [[ "$thunderbolt_response" =~ ^[Yy]$ ]]; then
    space_1
    conf_msg "Thunderbolt remains enabled"
    
else
    # Get a list of active Thunderbolt domains
    active_domains=$(boltctl list | awk '/connected/ {print $1}')

    # Disable each active domain
    for domain in $active_domains; do
        short_msg "Disabling Thunderbolt domain: $domain"
        boltctl disable "$domain"
    done
    echo "install thunderbolt /bin/true" | tee -a "$blacklist_file" > /dev/null
    space_1
    conf_msg "Thunderbolt has been disabled and added to the kernel module blacklist"
fi

space_2
space_1

# === DNSCRYPT-PROXY ===

# Install dnscrypt-proxy, inspired by update script available at https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Updates
INSTALL_DIR="/usr/local/sbin/dnscrypt-proxy"
LATEST_URL="https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"
DNSCRYPT_PUBLIC_KEY="RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5"
PLATFORM="linux"
CPU_ARCH="x86_64"
workdir="/usr/local/sbin/dnscrypt-proxy/tmp"
download_url="$(curl -sL "$LATEST_URL" | grep dnscrypt-proxy-${PLATFORM}_${CPU_ARCH}- | grep browser_download_url | head -1 | cut -d \" -f 4)"
download_file="dnscrypt-proxy-update.tar.gz"
download_url2="https://raw.githubusercontent.com/DNSCrypt/dnscrypt-proxy/master/utils/generate-domains-blocklist/generate-domains-blocklist.py"
download_file2="generate-domains-blocklist.py"

mkdir -p "$workdir"

short_msg "Downloading dnscrypt-proxy..."
space_1
curl --request GET -sL --url "$download_url" --output "$workdir/$download_file"
response=$?

if [ $response -ne 0 ]; then
    short_msg "${bold}[ERROR]${normal} Could not download file from '$download_url'" >&2
    rm -Rf "$workdir"
    return 1
fi

if [ -x "$(command -v minisign)" ]; then
    curl --request GET -sL --url "${download_url}.minisig" --output "$workdir/${download_file}.minisig"
    minisign -Vm "$workdir/$download_file" -P "$DNSCRYPT_PUBLIC_KEY"
    valid_file=$?

    if [ $valid_file -ne 0 ]; then
      short_msg "${bold}[ERROR]${normal} Downloaded file has failed signature verification. Update aborted." >&2
      rm -Rf "$workdir"
      return 1
    fi

else
    short_msg "${bold}[WARN]${normal} minisign is not installed, downloaded file signature could not be verified."
    space_1
fi

tar xz -C "$workdir" -f "$workdir/$download_file" "${PLATFORM}-${CPU_ARCH}/dnscrypt-proxy" "${PLATFORM}-${CPU_ARCH}/example-dnscrypt-proxy.toml"
mv -f "${workdir}/${PLATFORM}-${CPU_ARCH}"/* "${INSTALL_DIR}/"
mv -f "${INSTALL_DIR}/example-dnscrypt-proxy.toml" "${INSTALL_DIR}/dnscrypt-proxy.toml"

config_file="${INSTALL_DIR}/dnscrypt-proxy.toml"

# Add IPv6 support
sed -i "s/listen_addresses = ['127.0.0.1:53']/listen_addresses = ['[::]:53']/" "$config_file"

# Modify require_dnssec parameter
sed -i 's/require_dnssec = false/require_dnssec = true/' "$config_file"

# Uncomment blocked_names_file parameter and update its value
sed -i '/^# blocked_names_file =/ s/^# //' "$config_file"
sed -i "s/blocked-names.txt/blocklist.txt/" "$config_file"

# Basic ad blocking - get blocklist combining script
curl --request GET -sL --url "$download_url2" --output "$INSTALL_DIR/$download_file2"

# generate-domains-blocklist.py fails without this file
cat > "${INSTALL_DIR}/domains-time-restricted.txt" << EOF
## Rules to be applied at specific times
##
## This requires a time schedule to be defined in the
## dnscrypt-proxy.toml configuration file.
EOF

# generate-domains-blocklist.py fails without this file, too
cat > "${INSTALL_DIR}/domains-allowlist.txt" << EOF
## You can add domains here to allow. Allow list takes precendence over the blocklist.
EOF

# Add blocklist URLs to blocklist combining script config
cat > "${INSTALL_DIR}/domains-blocklist.conf" << EOF
## solidcore's dnscrypt-proxy blocklist config file
## 
## Add your own lists, or comment out (by adding # at the start of a line).

# === AD BLOCKING ===
# Green lists from firebog.net
https://adaway.org/hosts.txt
https://v.firebog.net/hosts/AdguardDNS.txt
https://v.firebog.net/hosts/Admiral.txt
https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt
https://v.firebog.net/hosts/Easylist.txt
https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext
https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts
https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts


# === ADULT CONTENT ===
#https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list
#https://v.firebog.net/hosts/Prigent-Adult.txt
#https://nsfw.oisd.nl/domainswild

# === MALICIOUS ===
# Green lists from firebog.net, the rest from https://github.com/PeterDaveHello/threat-hostlist and https://github.com/hagezi/dns-blocklists#tif
https://azorult-tracker.net/api/list/domain?format=plain
https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt
https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt
https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt
https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt
https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt
https://github.com/DandelionSprout/adfilt/raw/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/wildcard/tif-onlydomains.txt
https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt
https://hole.cert.pl/domains/domains.txt
https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt
https://openphish.com/feed.txt
https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts
https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt
https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-urls-pihole.txt
https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts
https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt
https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt
https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/master/src/hosts.txt
https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt
https://securereload.tech/Phishing/Lists/Latest/
https://v.firebog.net/hosts/Prigent-Crypto.txt
https://v.firebog.net/hosts/RPiList-Malware.txt
https://v.firebog.net/hosts/RPiList-Phishing.txt
https://www.usom.gov.tr/url-list.txt


# === MEGA LISTS ===
# DNSCrypt List by Frank Denis
https://download.dnscrypt.info/blocklists/domains/mybase.txt
# NoTracking
https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnscrypt-proxy/dnscrypt-proxy.blacklist.txt
# OISD
https://big.oisd.nl/domainswild
# Steven Black's Unified Hosts
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts


# === PRIVACY ===
# Green lists from firebog.net
https://v.firebog.net/hosts/Easyprivacy.txt
https://v.firebog.net/hosts/Prigent-Ads.txt
https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
EOF

# Create dnscrypt-proxy update script taken from https://github.com/DNSCrypt/dnscrypt-proxy/wiki/Updates
cat > "$INSTALL_DIR"/dnscrypt-proxy-update.sh << EOF
#! /bin/sh

INSTALL_DIR="/usr/local/sbin/dnscrypt-proxy"
LATEST_URL="https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"
DNSCRYPT_PUBLIC_KEY="RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5"
PLATFORM="linux"
CPU_ARCH="x86_64"

Update() {
  workdir="$(mktemp -d)"
  download_url="$(curl -sL "$LATEST_URL" | grep dnscrypt-proxy-${PLATFORM}_${CPU_ARCH}- | grep browser_download_url | head -1 | cut -d \" -f 4)"
  echo "[INFO] Downloading update from '$download_url'..."
  download_file="dnscrypt-proxy-update.tar.gz"
  curl --request GET -sL --url "$download_url" --output "$workdir/$download_file"
  response=$?

  if [ $response -ne 0 ]; then
    echo "[ERROR] Could not download file from '$download_url'" >&2
    rm -Rf "$workdir"
    return 1
  fi

  if [ -x "$(command -v minisign)" ]; then
    curl --request GET -sL --url "${download_url}.minisig" --output "$workdir/${download_file}.minisig"
    minisign -Vm "$workdir/$download_file" -P "$DNSCRYPT_PUBLIC_KEY"
    valid_file=$?

    if [ $valid_file -ne 0 ]; then
      echo "[ERROR] Downloaded file has failed signature verification. Update aborted." >&2
      rm -Rf "$workdir"
      return 1
    fi
  else
    echo '[WARN] minisign is not installed, downloaded file signature could not be verified.'
  fi

  echo '[INFO] Initiating update of DNSCrypt-proxy'

  tar xz -C "$workdir" -f "$workdir/$download_file" ${PLATFORM}-${CPU_ARCH}/dnscrypt-proxy &&
    mv -f "${INSTALL_DIR}/dnscrypt-proxy" "${INSTALL_DIR}/dnscrypt-proxy.old" &&
    mv -f "${workdir}/${PLATFORM}-${CPU_ARCH}/dnscrypt-proxy" "${INSTALL_DIR}/" &&
    chmod u+x "${INSTALL_DIR}/dnscrypt-proxy" &&
    cd "$INSTALL_DIR" &&
    ./dnscrypt-proxy -check && ./dnscrypt-proxy -service install 2>/dev/null || : &&
    ./dnscrypt-proxy -service restart || ./dnscrypt-proxy -service start

  updated_successfully=$?

  rm -Rf "$workdir"
  if [ $updated_successfully -eq 0 ]; then
    echo '[INFO] DNSCrypt-proxy has been successfully updated!'
    return 0
  else
    echo '[ERROR] Unable to complete DNSCrypt-proxy update. Update has been aborted.' >&2
    return 1
  fi
}

if [ ! -f "${INSTALL_DIR}/dnscrypt-proxy" ]; then
  echo "[ERROR] DNSCrypt-proxy is not installed in '${INSTALL_DIR}/dnscrypt-proxy'. Update aborted..." >&2
  exit 1
fi

local_version=$("${INSTALL_DIR}/dnscrypt-proxy" -version)
remote_version=$(curl -sL "$LATEST_URL" | grep "tag_name" | head -1 | cut -d \" -f 4)

if [ -z "$local_version" ] || [ -z "$remote_version" ]; then
  echo "[ERROR] Could not retrieve DNSCrypt-proxy version. Update aborted... " >&2
  exit 1
else
  echo "[INFO] local_version=$local_version, remote_version=$remote_version"
fi

if [ "$local_version" != "$remote_version" ]; then
  echo "[INFO] local_version not synced with remote_version, initiating update..."
  Update
  exit $?
else
  echo "[INFO] No updated needed."
  exit 0
fi
EOF

# Create the service file for dnscrypt-proxy update
cat > /etc/systemd/system/dnscrypt-proxy-update.service <<EOL
[Unit]
Description=Automatically update dnscrypt-proxy blocklist and application

[Service]
Type=oneshot
ExecStart=python3 ${INSTALL_DIR}/${download_file2} -c ${INSTALL_DIR}/domains-blocklist.conf -a ${INSTALL_DIR}/domains-allowlist.txt -r ${INSTALL_DIR}/${download_file3} -o ${INSTALL_DIR}/blocklist.txt.tmp && mv -f ${INSTALL_DIR}/blocklist.txt.tmp ${INSTALL_DIR}/blocklist.txt
ExecStart=${INSTALL_DIR}/dnscrypt-proxy-update.sh
EOL

# Create the timer file for dnscrypt-proxy update
cat > /etc/systemd/system/dnscrypt-proxy-update.timer <<EOL
[Unit]
Description=Run dnscrypt-proxy updates 20 seconds after boot and every day thereafter

[Timer]
Persistent=True
OnBootSec=20sec
OnCalendar=*-*-* 00:00:00


[Install]
WantedBy=timers.target
EOL

# Reload systemd configuration after creating the files
systemctl daemon-reload

# Restore SELinux policies to /usr/local/sbin
restorecon -Rv /usr/local/sbin

# Change permissions of all dnscrypt-proxy files
chown -R root "${INSTALL_DIR}/" 
chgrp -R root "${INSTALL_DIR}/"
chmod -R 775 "${INSTALL_DIR}/"

# Create blocklist file for dnscrypt-proxy
python3 "${INSTALL_DIR}/${download_file2}" -c "${INSTALL_DIR}/domains-blocklist.conf" -a "${INSTALL_DIR}/domains-allowlist.txt" -r "${INSTALL_DIR}/${download_file3}" -i -o "${INSTALL_DIR}/blocklist.txt"  > /dev/null

# Disable resolved
systemctl stop systemd-resolved
systemctl disable systemd-resolved > /dev/null 2>&1

# Replace resolv.conf
rm -rf /etc/resolv.conf
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
options edns0
EOF

# Install and start dnscrypt-proxy service, then tidy up
${INSTALL_DIR}/dnscrypt-proxy -service install
sleep 1

${INSTALL_DIR}/dnscrypt-proxy -service start > /dev/null
rm -Rf "$workdir"

space_1
conf_msg "dnscrypt-proxy installed"


# === MACHINE ID ===

new_machine_id="b08dfa6083e7567a1921a715000001fb"

# Change machine ID in /etc/machine-id
echo "$new_machine_id" | sudo tee /etc/machine-id > /dev/null

# Change machine ID in /var/lib/dbus/machine-id
echo "$new_machine_id" | sudo tee /var/lib/dbus/machine-id > /dev/null

space_1
conf_msg "Generic Machine ID applied"


# === START & ENABLE SYSTEMD SERVICES ===

systemd_timers=(
    "rpm-ostreed-automatic.timer"
    "flatpak-update.timer"
    "dnscrypt-proxy-update.timer"
)

for sc_timer in "${systemd_timers[@]}"; do
    systemctl enable --now "${sc_timer}" > /dev/null 2>&1
done

space_1
conf_msg "Automatic update timers initiated"
space_2


# === FINAL CHECKS ===

clear
long_msg ">
>
>  Running some final checks..."
sleep 2
space_2

# Check the current SELinux status and enable enforcing if required
short_msg "[1 of 3] Checking SELinux..."
space_1
sleep 1
current_status=$(sestatus | awk '/Current mode:/ {print $3}')
desired_status="enforcing"

if [ "$current_status" = "$desired_status" ]; then
    conf_msg "SELinux already set to enforcing"
else
    setenforce 1
    conf_msg "SELinux now set to enforcing"
fi
space_2

# HTTP check for the repos
short_msg "[2 of 3] Checking insecure URLs in the repo directory..."
space_1
sleep 1
patterns=("^baseurl=http:" "^metalink=http:")
for pattern in "${patterns[@]}"; do
    output=$(grep -r "$pattern" /etc/yum.repos.d/)
    if [ -n "$output" ]; then
        short_msg "${bold}[WARNING]${normal} HTTP link found in the repository directory (/etc/yum.repos.d/)."
        short_msg "Output:"
        short_msg "$output"
        short_msg "Please investigate. You may be able to manually edit the repo to use HTTPS. Failing that, contact the repo maintainer to report the security issue."
        sleep 2
    else
        conf_msg "No insecure repos found in the repository directory"
    fi
done
space_2

# CPU vulnerability check
short_msg "[3 of 3] Checking CPU Vulnerabilities..."
space_1
sleep 1

short_msg "Vulnerability      | Status"
short_msg "------------------ | --------------"

vulnerabilities=$(grep . /sys/devices/system/cpu/vulnerabilities/*)

while read -r line; do
    # Extract vulnerability and status using awk
    vulnerability=$(short_msg "$line" | awk -F ':' '{print $1}')
    status=$(short_msg "$line" | awk -F ':' '{print $2}')

    # Print the vulnerability and its status in a table format
    printf "%-18s | %s\n" "$vulnerability" "$status"
done <<< "$vulnerabilities"
sleep 1
space_1
short_msg "Please take a note of the vulnerability if there is no mitigation (Migitation: None)."
sleep 1
space_1
short_msg "Raise this vulnerability as an issue on the solidcore-script Github repo:"
short_msg "https://github.com/solidc0re/solidcore-scripts"
sleep 3
space_2

# === TiDY UP & FINISH ===

# Reboot if USB Guard installed, otherwise farewell
if [[ "$usb_response" =~ ^[Yy]$ ]]; then
    short_msg "Because you confirmed you use USB devices, a final reboot is required to deploy USBGuard."
    space_1
    short_msg "Another script will guide you through whitelisting your USB devices."
	sleep 2
    space_2
    read -n 1 -s -r -p "Press any key to continue..."
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
    # Remove first boot autostart
    rm /etc/xdg/autostart/solidcore-welcome.desktop > /dev/null 2>&1
    sleep 1
    # End
    short_msg "${bold}Thank you for running the solidcore script.${normal}"
	space_1
    short_msg "For some suggestions on what to do next, see:"
    short_msg "https://github.com/solidc0re/solidcore-scripts#post-install-information"
	space_1
    short_msg "Enjoy your new hardened immutable Fedora :)"
    space_2
    sleep 2
fi
echo