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

# Install script


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


# === FLAGS ===

# Server mode
# Check if the -server flag is provided
if [[ "$1" == "-server" ]]; then
    server_mode=true
    short_msg "Server mode: Some commands will not be executed."
else
    server_mode=false
fi

# Test mode
# Check if the -test flag is provided
if [[ "$1" == "-test" ]]; then
    test_mode=true
    short_msg "Test mode: Some commands will not be executed."
else
    test_mode=false
fi

# === INITIAL CHECKS ===

# Enable error tracing on -server flag
if [[ "$server_mode" == true ]]; then
    set -ouex pipefail
fi


# Sudo check
# Check if the script is being run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    short_msg "This script requires sudo privileges. Please run it with 'sudo' using 'sudo <path-to-script>./solidcore-install.sh'"
    sleep 1
    exit 1
fi

# Variant check
# Check immutable variant
# Define an array of immutable Fedora variants
declare -a fedora_variants=("silverblue" "kinoite" "sericea" "vauxite" "onyx")

# Initialize a variable to store the detected variant
detected_variant=""

# Run rpm-ostree status -b and capture the output
ostree_status=$(rpm-ostree status -b)

# Iterate through the array to check for a match
for variant in "${fedora_variants[@]}"; do
    if [[ "$ostree_status" == *"$variant"* ]]; then
        detected_variant="$variant"
        break  # Exit the loop after the first match
    fi
done

# Use the detected_variant variable later in your script
if [ -n "$detected_variant" ]; then
    :
else
    short_msg "No supported immutable Fedora variant detected."
    exit 1
fi


# === WELCOME ===

RELEASE="$(rpm -E %fedora)"

if [[ "$server_mode" == true ]]; then
    solidcore_response="Y"
else
clear
long_msg ">
>
>
>  Welcome to solidcore!
>
>  The hardening script for immutable Fedora variants.
>
>  You are currently running: ${detected_variant^} $RELEASE."

sleep 1
long_msg "
>
>
>  This script will carry out various hardening measures, including:
>
>  1. Kernel and physical hardening to reduce attack surface
>  2. Drop all incoming connections, prevent IP spoofing and protect against various forms of attack
>  3. Hide sensitive kernel and file information from potential attackers
>  4. Stengthen password policies
>  5. Enable automatic updates for rpm-ostree and flatpaks"

sleep 1
long_msg "
>
>
>  This script is open source (GPLv3) and has been tested on Silverblue 38 by the author.
>
>  Hardening MAY reduce your experience of your device and is not suited for everyone."

sleep 2
space_2

while true; do
read -p "Do you want to continue? (y/n): " solidcore_response
case $solidcore_response in 
	[Yy] ) solidcore_response="Y";
		break;;
	[Nn] ) short_msg "Aborting."
        space_2
        sleep 
        clear;
		exit 1;;
	* ) short_msg "Invalid response. Please retry with 'y' or 'n'."
        echo ">";
esac
done

fi

if [[ "$solidcore_response" =~ ^[Yy]$ ]]; then
long_msg ">
>
>  Your system will reboot once the first round of hardening is completed.
>  You will be presented with another script on first boot.
>  Be sure to complete all the stages to finish the hardening process.
>
>  Starting...
>
>"
sleep 3

# === SYSCTL PARAMETERS ===

# Array of sysctl commands and their new settings
declare -A sysctl_settings
    # KERNEL
    sysctl_settings["kernel.kptr_restrict"]="2" # Mitigate kernel pointer leaks
    sysctl_settings["kernel.dmesg_restrict"]="1" # Restrict kernel log
    sysctl_settings["kernel.printk"]="3 3 3 3" # Stop printing kernel log on boot
    sysctl_settings["kernel.unprivileged_bpf_disabled"]="1" # Restrict eBPF
    sysctl_settings["net.core.bpf_jit_harden"]="2"
    sysctl_settings["dev.tty.ldisc_autoload"]="0" # Restrict loading TTY line disciplines
    sysctl_settings["kernel.kexec_load_disabled"]="1" # Disable kexec
    sysctl_settings["kernel.sysrq"]="0" # Disable SysRq
    sysctl_settings["kernel.perf_event_paranoid"]="3" # Restrict usage of performance events
    # NETWORK
    sysctl_settings["net.ipv4.tcp_syncookies"]="1" # Protect against SYN flood attacks
    sysctl_settings["net.ipv4.tcp_rfc1337"]="1" # Protect against time-wait assassination
    sysctl_settings["net.ipv4.conf.all.rp_filter"]="1" # Protect against IP spoofing
    sysctl_settings["net.ipv4.conf.default.rp_filter"]="1"
    sysctl_settings["net.ipv4.conf.all.accept_redirects"]="0" # Disable ICMP redirect acceptance
    sysctl_settings["net.ipv4.conf.default.accept_redirects"]="0"
    sysctl_settings["net.ipv4.conf.all.secure_redirects"]="0"
    sysctl_settings["net.ipv4.conf.default.secure_redirects"]="0"
    sysctl_settings["net.ipv6.conf.all.accept_redirects"]="0"
    sysctl_settings["net.ipv6.conf.default.accept_redirects"]="0"
    sysctl_settings["net.ipv4.conf.all.send_redirects"]="0"
    sysctl_settings["net.ipv4.conf.default.send_redirects"]="0"
    sysctl_settings["net.ipv4.icmp_echo_ignore_all"]="1" # Prevent smurf attacks and clock fingerprinting
    sysctl_settings["net.ipv6.conf.all.accept_ra"]="0" # Disable IPv6 router advertisements
    sysctl_settings["net.ipv6.conf.default.accept_ra"]="0"
    sysctl_settings["net.ipv4.tcp_sack"]="0" # Disable TCP SACK
    sysctl_settings["net.ipv4.tcp_dsack"]="0"
    sysctl_settings["net.ipv4.tcp_fack"]="0"
    sysctl_settings["net.ipv4.tcp_timestamps"]="0" # Disable TCP timestamps
    sysctl_settings["net.ipv6.conf.all.use_tempaddr"]="2" # Generate random IPv6 addresses
    sysctl_settings["net.ipv6.conf.default.use_tempaddr"]="2"
    # USERSPACE
    sysctl_settings["kernel.yama.ptrace_scope"]="2" # Restrict ptrace
    sysctl_settings["vm.mmap_rnd_bits"]="32" # Increase mmap ALSR entropy
    sysctl_settings["vm.mmap_rnd_compat_bits"]="16"
    sysctl_settings["fs.protected_fifos"]="2" # Prevent creating files in potential attacker-controlled directories
    sysctl_settings["fs.protected_regular"]="2"


# === BACKUPS & RESTORE FILE ===

# Create the directory if it doesn't exist
mkdir -p /etc/solidcore

# Only do the backing up and creation of default scripts if server mode is not flagged
if [[ "$server_mode" == false ]]; then

# Output default settings to the new script
echo "#!/bin/bash" > /etc/solidcore/defaults.sh
echo "# Previous sysctl values. Created by solidcore script." >> /etc/solidcore/defaults.sh
for key in "${!sysctl_settings[@]}"; do
    # Get the existing sysctl value
    existing_value=$(sysctl -n "$key")
    echo "sysctl -w $key=$existing_value" >> /etc/solidcore/defaults.sh
done
chmod +x /etc/solidcore/defaults.sh

# Define an array of files to be backed up
files_to_backup=(
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

# Loop through the array and create backup copies
for source_file in "${files_to_backup[@]}"; do
    # Check if the source file exists
    if [ -e "$source_file" ]; then
        # Construct the backup filename
        backup_file="${source_file}_sc.bak"
        # Copy the source file to the backup file
        cp "$source_file" "$backup_file"
    fi
done
conf_msg "All backups created"
fi # End of -server flag if statement

# === APPLY SYSCTL SETTINGS ===

# Apply new sysctl settings
for key in "${!sysctl_settings[@]}"; do
    sysctl -w "$key=${sysctl_settings[$key]}" > /dev/null
done
conf_msg "Hardened sysctl settings applied"

# === BOOTLOADER SETTINGS ===

# Check CPU vendor using lscpu
cpu_vendor=$(lscpu | awk '/Vendor/ {print $3}')

# Boot parameters to be added
boot_parameters=(
    "slab_nomerge" # Disables slab merging
    "init_on_alloc=1" # Enables zeroing of memory to mitigate use-after-free vulnerabilities
    "init_on_free=1"
    "page_alloc.shuffle=1" # Improve security by making page allocation less predictable
    "pti=on" # Mitigate Meltdown and prevents some KASLR bypasses
    "randomize_kstack_offset=on" # Randomises kernel stack offset on each syscall
    "vsyscall=none" # Disables obsolete vsyscalls
    "debugfs=off" # Disables debugfs to stop sensitive information being exposed
    "lockdown=confidentiality" # Makes it harder to load malicious kernel modules; mplies module.sig_enforce=1 so could break unsigned drivers (NVIDIA, etc.)
    "quiet loglevel=0" # Prevents information leaks on boot; must be used in conjuction with kernel.printk sysctl
    #"ipv6.disable=1"
    "random.trust_cpu=off" # Do not trust proprietary code on CPU for random number generation
    "efi=disable_early_pci_dma" # Fixes hole in IOMMU
    "mitigations=auto" # Ensures mitigations against known CPU vulnerabilities
)

# Add IOMMU parameter based on CPU vendor
case "$cpu_vendor" in
    GenuineIntel*) boot_parameters+=("intel_iommu=on") ;;
    AuthenticAMD*) boot_parameters+=("amd_iommu=on") ;;
    *) echo "Notice: CPU vendor doesn't match GenuineIntel or AuthenticAMD. CPU Vendor currently recorded as: $cpu_vendor" ;;
esac

# Construct the new GRUB_CMDLINE_LINUX_DEFAULT value
new_cmdline="GRUB_CMDLINE_LINUX_DEFAULT=\"${boot_parameters[*]}\""

# Update the /etc/default/grub file
if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub; then
    # If the line already exists, replace it
    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|$new_cmdline|" /etc/default/grub
else
    # If the line doesn't exist, add it at the end of the file
    echo "$new_cmdline" >> /etc/default/grub
fi

# Run update-grub to update GRUB configuration
if [[ "$test_mode" == false ]]; then
    if grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null 2>&1 ; then
        conf_msg "GRUB configuration updated"
    else
        short_msg "Notice: Failed to update GRUB configuration."
    fi
else
    conf_msg "Testing. Skipped updating of GRUB configuration."
fi


# === BLACKLIST KERNEL MODULES === 

blacklist_file="/etc/modprobe.d/solidcore-blacklist.conf"

# List of module names to be blacklisted
modules_to_blacklist=(    
    "af_802154"
    #"appletalk" # Already blacklisted in Fedora
    #"atm" # Already backlisted in Fedora 
    #"ax25" # Already blacklisted in Fedora
    "can"
    "cifs"
    "cramfs"
    "decnet"
    "dccp"
    "econet"
    "freevxfs"
    "gfs2"
    "hfs"
    "hfsplus"
    "ipx"
    "jffs2"
    "ksmbd"
    "n-hdlc"
    #"netrom" # Already blacklisted in Fedora
    "nfsv3"
    "nfsv4"
    "nfs"
    "p8022"
    "p8023"
    "psnap"
    #"rds" # Already blacklisted in Fedora
    #"rose" # Already blacklisted in Fedora
    #"sctp" # Already blacklisted in Fedora
    "squashfs"
    "tipc"
    "udf"
    "vivid"
    "x25"
)

# Add module names to the blacklist configuration file
echo "# Blacklisted kernel modules to prevent loading. Created by solidcore script." | tee "$blacklist_file" > /dev/null
for module in "${modules_to_blacklist[@]}"; do
    echo "blacklist $module" | tee -a "$blacklist_file" > /dev/null
done

conf_msg "Kernel modules blacklisted"


# === DISABLE SERVICES ===

# High risk and unused services/sockets
services=(
    #abrt-journal-core.service # Not found in F38
    #abrt-oops.service # Fedora crash reporting
    #abrtd.service # Fedora crashing reporting
    avahi-daemon # Recommended by CIS
    geoclue.service # Location service
    httpd # Recommended by CIS
    network-online.target # Remote file mounting, most likely unncessary
    nfs-server # Recommended by CIS
    remote-fs.target # Remote file mounting, most likely unnecessary
    rpcbind # Recommended by CIS
    rpm-ostree-countme.service # Potential to leak information about OS to someone monitoring network
    sshd # Not needed on desktop
)

# Loop through the array and stop and disable each service/socket
for service in "${services[@]}"; do
    # Check if the service exists
    if systemctl list-units --all | grep -q "^$service"; then
        # Stop the service/socket
        systemctl stop "$service"
        # Disable the service/socket
        systemctl disable "$service" > /dev/null
        # Mask service/socket
        systemctl --now mask "$service" > /dev/null
        # Reload systemd after masking
        systemctl daemon-reload
    fi
done

conf_msg "High risk and unnecessary services disabled"

# === HIDEPID ===

# Add line to /etc/fstab
fstab_line="proc /proc proc nosuid,nodev,noexec,hidepid=2 0 0"
echo "$fstab_line" | tee -a /etc/fstab > /dev/null
systemctl daemon-reload

conf_msg "hidepid enabled for /proc"


# === FILE PERMISSIONS ===

# Ensure new files are only readable by the user who created them
umask_script="/etc/profile.d/solidcore_umask.sh"

# Create the umask script
echo '#!/bin/bash' | tee "$umask_script" > /dev/null
echo 'umask 0077' | tee -a "$umask_script" > /dev/null

# Make the script executable
chmod +x "$umask_script"

conf_msg "Newly created files now only readable by user that created them"


# === DISABLE CORE DUMPS ===

# Temporarily disable core dumps until next reboot
ulimit -c 0

# Purge old core dumps
systemd-tmpfiles --clean 2> /dev/null

# Add a line to disable core dumps in limits.conf
echo "* hard core 0" | tee -a /etc/security/limits.conf > /dev/null

# Update the coredump.conf file
echo "[Coredump]" | tee /etc/systemd/coredump.conf > /dev/null
echo "Storage=none" | tee -a /etc/systemd/coredump.conf > /dev/null
echo "ProcessSizeMax=0" | tee -a /etc/systemd/coredump.conf > /dev/null
echo "ExternalSizeMax=0" | tee -a /etc/systemd/coredump.conf > /dev/null

# Reload systemctl configs
systemctl daemon-reload

conf_msg "Core dumps disabled"


# === PASSWORD POLICIES ===

# Create a custom authselect profile called "solidcore"
authselect create-profile solidcore -b sssd > /dev/null 2>&1

# Increase password delay from 2 second default to 5 seconds
new_delay="5000000"

# Remove ability for someone to set an empty password
text_to_remove=" {if not \"without-nullok\":nullok}"

# Define the files to modify
pwd_files=(
    "/etc/authselect/custom/solidcore/password-auth"
    "/etc/authselect/custom/solidcore/system-auth"
)

# Loop through the files and update the line
for file in "${pwd_files[@]}"; do
    # Check if the file exists
    if [ -f "$file" ]; then
        # Use sed to replace the line with the new value
        sed -i "s/\(auth\s*required\s*pam_faildelay.so\s*delay=\).*$/\1$new_delay/" "$file"
	    # Remove nullok reference
 	    sed -i "s/$text_to_remove//" "$file"
  	    # Append minimum length of 12
        sed -i "/pam_pwquality.so/s/$/ minlen=12/" "$file"
    else
        echo "File not found: $file"
    fi
done

# Apply the custom profile
authselect select custom/solidcore > /dev/null 2>&1
conf_msg "Custom password profile 'solidcore' created and applied"


# === LOCK ROOT ===

# Uncomment the PermitRootLogin line in sshd_config, should someone ever enable it on their desktop
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Lock root account
passwd -l root > /dev/null
conf_msg "Root account locked"


# === FIREWALL D ===

# Drop all incoming connections
firewall-cmd --set-default-zone drop > /dev/null 2>&1
firewall-cmd --reload > /dev/null
conf_msg "Firewalld updated so only outgoing connections are permitted"


# === HTTPS REPO CHECK ===

# Define an array of patterns to search for
patterns=("^baseurl=http:" "^metalink=http:")

# Loop through the patterns and perform checks
for pattern in "${patterns[@]}"; do
    output=$(grep -r "$pattern" /etc/yum.repos.d/)
    if [ -n "$output" ]; then
        echo "Warning: HTTP link found in yum repository configuration."
        echo "Output:"
        echo "$output"
        echo "Please investigate whether you can manually edit the repo to use HTTPS instead."
    fi
done

conf_msg "No insecure repos found in yum repository directory"


# === AUTOMATIC UPDATES ===

# RPM-OSTREE 

# Update the rpm-ostree timer to trigger updates 10 minutes after boot and every 3 hours

timer_dir="/etc/systemd/system/rpm-ostreed-automatic.timer.d"
override_file="$timer_dir/override.conf"

# Check if the override.conf file exists
if [ -f "$override_file" ]; then
    # Remove the original file
    rm "$override_file"
fi

mkdir -p "$timer_dir"

cat > "$override_file" <<EOL
[Unit]
Description=Run rpm-ostree updates 10 minutes after boot and every 3 hours

[Timer]
Persistent=True
OnBootSec=10min
OnCalendar=*-*-* *:0/3

[Install]
WantedBy=timers.target
EOL

# Update AutomaticUpdatePolicy to automatically stage updates
sed -i 's/^AutomaticUpdatePolicy=.*/AutomaticUpdatePolicy=stage/' /etc/rpm-ostreed.conf

# Reload systemd configuration after modifying the timer
systemctl daemon-reload

conf_msg "Automatic rpm-ostree update timer installed"

# FLATPAK

# Enable Flathub
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak remote-modify --no-filter --enable flathub

# Change remotes of existing flathub apps
short_msg "Replacing Fedora flatpaks with Flathub versions. This will take a while..."

# Create undo script only if -server flag absent
if [[ "$server_mode" == false ]]; then
echo "#!/bin/bash" > /etc/solidcore/fedora_flatpak.sh
echo "flatpak remote-modify --enable fedora" >> /etc/solidcore/fedora_flatpak.sh

# Get a list of Fedora flatpaks and output install commands
flatpak list --app-runtime=org.fedoraproject.Platform --columns=application | tail -n +2 | while read -r flatpak_name; do
    echo "flatpak install -y --noninteractive --reinstall fedora $flatpak_name" >> /etc/solidcore/fedora_flatpak.sh
done

# Make executable
chmod +x /etc/solidcore/fedora_flatpak.sh
fi # End of -server flag if statement

# Replace Fedora flatpaks and install flathub versions
flatpak list --app-runtime=org.fedoraproject.Platform --columns=application | tail -n +2 | while read -r flatpak_name; do
    flatpak install -y --noninteractive --reinstall flathub "$flatpak_name" > /dev/null 2>&1
done
conf_msg "Done"

# Disable Fedora flatpak repo
flatpak remote-modify --disable fedora

# Create the service file for Flatpak update
cat > /etc/systemd/system/flatpak-update.service <<EOL
[Unit]
Description=Automatically update Flatpak applications

[Service]
Type=oneshot
ExecStart=/usr/bin/flatpak uninstall --unused -y --noninteractive && \
          /usr/bin/flatpak update -y --noninteractive && \
          /usr/bin/flatpak repair
EOL

# Create the timer file for Flatpak update
cat > /etc/systemd/system/flatpak-update.timer <<EOL
[Unit]
Description=Run Flatpak updates 20 minutes after boot and every 3 hours and 10 minute

[Timer]
Persistent=True
OnBootSec=20min
OnCalendar=*-*-* *:10/3


[Install]
WantedBy=timers.target
EOL

# Reload systemd configuration after creating the files
systemctl daemon-reload

conf_msg "Automatic Flatpak update timer installed"


# === MISC ===

# Create a xdg autostart file to mute microphone on boot
cat > /etc/xdg/autostart/solidcore-mute-mic.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Solidcore Script to Mute Microphone on Boot
Exec=amixer set Capture nocap
Icon=utilities-terminal
EOF

chmod 644 /etc/xdg/autostart/solidcore-mute-mic.desktop


# === INSTALLS ===

#short_msg "Installing minisign (for dnscrypt-proxy installation & updates). This will also take a while..."
#space_1

# Minisign
#rpm-ostree install minisign > /dev/null
#conf_msg "Done"

# Flatseal
flatpak install -y com.github.tchx84.Flatseal > /dev/null 2>&1
conf_msg "Flatseal installed (for managing Flatpak permissions)"


# === SETUP FIRSTBOOT ===

# Check if solidcore-firstboot.sh exists in the working directory
if [ -e "$PWD/solidcore-firstboot.sh" ]; then
    :
else
    # Download solidcore-firstboot.sh
    wget -q https://raw.githubusercontent.com/solidc0re/solidcore-scripts/main/solidcore-firstboot.sh
fi

# Make solidcore-firstboot.sh executable
chmod +x solidcore-firstboot.sh

# Create the directory if it doesn't exist
mkdir -p /etc/solidcore

# Move the file to /etc/solidcore/
mv -f "solidcore-firstboot.sh" "/etc/solidcore/"

# Create first boot loader
cat > /etc/solidcore/solidcore-welcome.sh << EOF
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

# Welcome script


# === RUN FIRSTBOOT ===
clear
echo ">"
echo ">"
echo "> Please enter your sudo password to continue with the solidcore process."
sudo bash /etc/solidcore/solidcore-firstboot.sh
EOF

# Make executable
chmod +x /etc/solidcore/solidcore-welcome.sh

# Create a xdg autostart file
cat > /etc/xdg/autostart/solidcore-welcome.desktop << EOF
[Desktop Entry]
Type=Application
Name=Solidcore Script to Run on First Boot
Exec=/etc/solidcore/solidcore-welcome.sh
Terminal=true
Icon=utilities-terminal
EOF

conf_msg "Set up first boot script"

# === INSTALL UNINSTALL SCRIPT ===

# Check if the -server flag is provided
if [[ "$server_mode" == false ]]; then
    if [ -e "$PWD/solidcore-uninstall.sh" ]; then
        :
    else
        # Download solidcore-uninstall.sh
        wget -q https://raw.githubusercontent.com/solidc0re/solidcore-scripts/main/solidcore-uninstall.sh
    fi

    # Make solidcore-uninstall.sh executable
    chmod +x solidcore-uninstall.sh

    # Move the file to /etc/solidcore/
    mv -f "solidcore-uninstall.sh" "/etc/solidcore/"

# Create uninstall alias
cat > /etc/profile.d/solidcore.sh << EOF
solidcore() {
    if [ "$1"= "uninstall" ]; then
        shift
        sudo bash /etc/solidcore/uninstall.sh
    else
        echo "solidcore: error - use 'solidcore uninstall' to uninstall."
    fi
}
EOF
fi

conf_msg "Downloaded uninstall script for future use"
space_2

# === REBOOT ===
if [[ "$test_mode" == false && "$server_mode" == false ]]; then
    short_msg "${bold}Reboot required.${normal}"
    sleep 2
    space_2
    read -n 1 -s -r -p "Press any key to continue"
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
    conf_msg "Script completed"
fi

# === UNSOLID ===
# Pressed no to original question?
fi
