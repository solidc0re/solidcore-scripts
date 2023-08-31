#!/bin/bash

# Solidcore first boot script
# Contains all client-side hardening settings to make porting to the image builds easier.

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
>"
}


# Create one line gap

space_1() {
    long_msg "
>"
}


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
short_msg "You are now required to set a new password. 12 characters minimum!"
space_1
short_msg "Enter it below."
space_1
passwd > /dev/null
space_1
conf_msg "New password set"
space_2

# === HOSTNAME ===

# Ask the user if they want to set a new generic hostname
while true; do
read -rp "  Question: Do you want to set a generic hostname [recommended]? (y/n)`echo $'\n>  Examples include 'hostname', 'host', 'computer', etc. :  '`" hostname_response
case $hostname_response in 
	[Yy] ) hostname_response="Y";
		break;;
	[Nn] )
        break;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
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
    space_2    
else
    space_1
    short_msg "Skipping..."
    space_2
fi


# === GRUB ===

# Ask the user if they want to set a GRUB password
while true; do
read -rp "  Question: Do you want to set a GRUB password [recommended]? (y/n): " grub_response
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
    # Generate a new GRUB password hash
    read -rsp "Enter the new GRUB password: " password
    echo
    password_hash=$(echo -n "$password" | grub-mkpasswd-pbkdf2)

    # Update the GRUB configuration file
    new_entry="set superusers=\"root\"\npassword_pbkdf2 root $password_hash"
    sed -i "/^set superusers/d" /etc/grub.d/40_custom
    echo -e "$new_entry" | tee -a /etc/grub.d/40_custom > /dev/null

    # Regenerate the GRUB configuration
    grub-mkconfig -o /boot/grub/grub.cfg
    conf_msg "GRUB password updated"
    space_2
else
    space_1
    short_msg "Skipping..."
    space_2
fi


# === CUPS ===

# Enable or disable CUPS based on user response
while true; do
read -rp "  Question: Do you use a printer? (y/n): " printer_response
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
    space_2
else
    # User didn't confirm using a printer, disable CUPS
    systemctl stop cups
    systemctl disable cups > /dev/null 2>&1
    systemctl --now mask cups > /dev/null 2>&1
    systemctl daemon-reload
    conf_msg "Printer service (CUPS) has been stopped and disabled"
    space_2
fi


# === USB ===

# Install USBGuard or disable USB based on user response
while true; do
read -rp "  Question: Do you use any USB devices? (y/n): " usb_response
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
        
space_2
short_msg "This final solidcore script finishes USBGuard setup."
sleep 3
space_2


# === USBGUARD ===

# Ask user to plugin all used USB devices
short_msg "USBGuard setup: plugin the USB devices you wish to whitelist.
read -n 1 -s -r -p "  Once you've plugged them in, press any key to continue."
        
# Get USB device IDs and create whitelist rules
sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'

# Increase hardening and privacy of USBGuard
# usbguard set-parameter PresentControllerPolicy=apply-policy
# usbguard set-parameter HidePII=true

# Reload usbguard service to apply the new rules
systemctl enable --now usbguard.service > /dev/null
conf_msg "USBGuard enabled and all connected USB devices whitelisted"
sleep 1
space_2
short_msg "To whitelist devices in future, run:"
space_1
short_msg "$ sudo usbguard list-devices"
space_1
short_msg "Followed by:
space_1
short_msg "$ sudo usbguard allow-device <device number>
sleep 2


# === TIDY UP & FINISH ===

rm /etc/xdg/autostart/solidcore-secondboot.desktop
space_2
short_msg "Thank you for running the solidcore script."
space_1
short_msg "Please use the github page to report any issues and suggest improvements."
short_msg "If you encounter any issues or have any further hardening suggestions then please report them on Github."
short_msg "https://github.com/solidc0re/solidcore-scripts"
space_1
short_msg "Enjoy your new hardened immutable Fedora :)"
space_2
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
    space_2
    
    while true; do
    
    read -rp "  Question: Do you use any hardware security keys? (y/n): " token_response
    
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
    rmmod usbcore usb_storage > /dev/null 2>&1
    blacklist_file="/etc/modprobe.d/solidcore-blacklist.conf"
    echo "blacklist usb_storage" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist usbcore" | tee -a "$blacklist_file" > /dev/null
    conf_msg "USB has been disabled and added to the kernel module blacklist"
    space_2
fi


# === WEBCAM ===

# Enable or disable the webcam based on user response

while true; do

read -rp "  Question: If you have a non-USB connect webcam, such as an in-built one in a laptop, do you ever use it? (y/n): " webcam_response

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
    conf_msg "Webcam remains enabled"
    space_2
else
    rmmod uvcvideo > /dev/null 2>&1
    echo "blacklist uvcvideo" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Webcam has been disabled and added to the kernel module blacklist"
    space_2
fi


# === WIFI ===

# Enable or disable Wi-Fi based on user response

while true; do

read -rp "  Question: Do you use Wi-Fi? (y/n): " wifi_response

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
    conf_msg "All wireless devices, except Wi-Fi have been disabled"
    space_2
else
    rfkill block all
    conf_msg "All wireless devices have been disabled"
    space_2
fi


# === BLUETOOTH ===

# Enable or disable Bluetooth based on user response

while true; do

read -rp "  Question: Do you use any Bluetooth connected devices? (y/n): " bluetooth_response

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
    conf_msg "Bluetooth has been re-enabled"
    space_2
else
    systemctl stop bluetooth.service
    systemctl disable bluetooth.service > /dev/null 2>&1
    systemctl --now mask bluetooth.service > /dev/null 2>&1
    systemctl daemon-reload
    echo "blacklist bluetooth" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist btusb" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Bluetooth has been disabled and added to the kernel module blacklist"
    space_2
fi

# === FIREWIRE ===

# Enable or disable Firewire based on user response

while true; do

read -rp "  Question: Do you use any Firewire connected devices? (y/n): " firewire_response

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
    conf_msg "Firewire remains enabled"
    space_2
else
    rmmod ohci1394 sbp2 firewire_core > /dev/null 2>&1
    echo "blacklist firewire-core" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist ohcil394" | tee -a "$blacklist_file" > /dev/null
    echo "blacklist sbp2" | tee -a "$blacklist_file" > /dev/null
    conf_msg "Firewire has been disabled and added to the kernel module blacklist"
    space_2
fi

# === THUNDERBOLT ===

# Enable or disable thunderbolt based on user response

while true; do

read -rp "  Question: Do you use any Thunderbolt connected devices? (y/n): " thunderbolt_response

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
    conf_msg "Thunderbolt remains enabled"
    space_2
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
    space_2
fi


# === AUTOMATED TASKS ===

# Install dnscrypt-proxy
INSTALL_DIR="/opt/dnscrypt-proxy"
LATEST_URL="https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"
PLATFORM="linux"
CPU_ARCH="x86_64"
workdir="/opt/dnscrypt-proxy/tmp"
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
    short_msg "[ERROR] Could not download file from '$download_url'" >&2
    rm -Rf "$workdir"
    return 1
fi

if [ -x "$(command -v minisign)" ]; then
    curl --request GET -sL --url "${download_url}.minisig" --output "$workdir/${download_file}.minisig"
    minisign -Vm "$workdir/$download_file" -P "$DNSCRYPT_PUBLIC_KEY"
    valid_file=$?

    if [ $valid_file -ne 0 ]; then
      short_msg "[ERROR] Downloaded file has failed signature verification. Update aborted." >&2
      rm -Rf "$workdir"
      return 1
    fi

else
    short_msg '[WARN] minisign is not installed, downloaded file signature could not be verified.'
fi

tar xz -C "$workdir" -f "$workdir/$download_file" "${PLATFORM}-${CPU_ARCH}/dnscrypt-proxy" "${PLATFORM}-${CPU_ARCH}/example-dnscrypt-proxy.toml"
mv -f "${workdir}/${PLATFORM}-${CPU_ARCH}"/* "${INSTALL_DIR}/"
chmod u+x "${INSTALL_DIR}/dnscrypt-proxy"
mv -f "${INSTALL_DIR}/example-dnscrypt-proxy.toml" "${INSTALL_DIR}/dnscrypt-proxy.toml"

config_file="${INSTALL_DIR}/dnscrypt-proxy.toml"

# Modify require_dnssec parameter
sed -i 's/require_dnssec = false/require_dnssec = true/' "$config_file"

# Uncomment blocked_names_file parameter and update its value
sed -i '/^# blocked_names_file =/ s/^# //' "$config_file"
sed -i "s/blocked-names.txt/blocklist.txt/" "$config_file"

# Basic ad blocking - get blocklist combining script
curl --request GET -sL --url "$download_url2" --output "$INSTALL_DIR/$download_file2"

# Add blocklist URLs to blocklist combining script config
cat > "${INSTALL_DIR}/domains-blocklist.conf" << EOF
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

# === MALICIOUS ===
# Green lists from firebog.net
https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt
https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt
https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt
https://v.firebog.net/hosts/Prigent-Crypto.txt
https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts
https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt
https://phishing.army/download/phishing_army_blocklist_extended.txt
https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt
https://v.firebog.net/hosts/RPiList-Malware.txt
https://v.firebog.net/hosts/RPiList-Phishing.txt
https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt
https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts
https://urlhaus.abuse.ch/downloads/hostfile/


# === PRIVACY ===
# Green lists from firebog.net
https://v.firebog.net/hosts/Easyprivacy.txt
https://v.firebog.net/hosts/Prigent-Ads.txt
https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts
https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt
https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt
EOF

# Create blocklist file for dnscrypt-proxy
python3 "${INSTALL_DIR}/generate-domains-blocklist.py" -o blocklist.txt

# Disable resolved
systemctl stop systemd-resolved
systemctl disable systemd-resolved > /dev/null 2>&1

# Replace resolv.conf
rm -rf /etc/resolv.conf
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
options edns0
EOF

${INSTALL_DIR}/dnscrypt-proxy -check
${INSTALL_DIR}/dnscrypt-proxy -service install > /dev/null
${INSTALL_DIR}/dnscrypt-proxy -service start

#rm -Rf "$workdir"

conf_msg 'dnscrypt-proxy installed'


# Install dnscrypt-proxy updater

# Create dnscrypt-proxy update script
cat > "$INSTALL_DIR"/dnscrypt-proxy-update.sh << EOF
#! /bin/sh

INSTALL_DIR="/opt/dnscrypt-proxy"
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

chmod +x "${INSTALL_DIR}"/dnscrypt-proxy-update.sh

conf_msg "dnscrypt-proxy update script created"

# Create the service file for dnscrypt-proxy update
cat > /etc/systemd/system/dnscrypt-proxy-update.service <<EOL
[Unit]
Description=Automatically update dnscrypt-proxy blocklist and application

[Service]
Type=oneshot
ExecStart=python3 '${INSTALL_DIR}'/generate-domains-blocklist.py -o blocklist.txt
ExecStart='${INSTALL_DIR}'/dnscrypt-proxy-update.sh
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

conf_msg "dnscrypt-proxy update timer installed"

# Whonix Machine ID
new_machine_id="b08dfa6083e7567a1921a715000001fb"

# Change machine ID in /etc/machine-id
echo "$new_machine_id" | sudo tee /etc/machine-id > /dev/null

# Change machine ID in /var/lib/dbus/machine-id
echo "$new_machine_id" | sudo tee /var/lib/dbus/machine-id > /dev/null

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

conf_msg "Automatic update timers initiated"
space_2

# === TiDY UP & FINISH ===

# Remove first boot autostart
rm /etc/exg/autostart/solidcore-firstboot.desktop > /dev/null 2>&1

# Display notice regarding additional 
sleep 1
short_msg "Blacklisted kernel modules will not load on next reboot. They have been temporarily disabled until then."
space_2
sleep 1

# Reboot if USB Guard installed, otherwise farewell
if [[ "$usb_response" =~ ^[Yy]$ ]]; then
	short_msg "Because you confirmed you use USB devices, a final reboot is required to deploy USBGuard. Another script will guide you through whitelisting your USB devices."
	space_1
    read -n 1 -s -r -p "  Press any key to continue"
    space_2
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
    short_msg "Thank you for running the solidcore script."
	space_1
    short_msg "Please use the github page to report any issues and suggest improvements."
	space_1
    short_msg "If you encounter any issues or have any further hardening suggestions then please report them on Github."
    space_1
    short_msg "https://github.com/solidc0re/solidcore-scripts"
	space_1
    short_msg "Enjoy your new hardened immutable Fedora :)"
    space_2
    sleep 2
fi
echo
