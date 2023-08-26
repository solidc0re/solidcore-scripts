#!/bin/bash

# Solidcore Hardening Script for Fedora's rpm-ostree Operating Systems

# Resources:
# https://madaidans-insecurities.github.io/guides/linux-hardening.html
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
# https://wiki.archlinux.org/
# https://www.cisecurity.org/benchmark/red_hat_linux
# https://www.cisecurity.org/benchmark/distribution_independent_linux
# https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
# https://github.com/a13xp0p0v/kconfig-hardened-check/


# === INITIAL CHECKS ===

# Test mode
# Check if the -test flag is provided
if [[ "$1" == "-test" ]]; then
    test_mode=true
    echo "Test mode: Some commands will not be executed."
else
    test_mode=false
fi

# Sudo check
# Check if the script is being run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script requires sudo privileges. Please run it with 'sudo' using 'sudo <path-to-script>./solidcore-install.sh'"
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
    echo "No supported immutable Fedora variant detected."
    exit 1
fi

# === WELCOME ===

typeit() {
 local IFS=''
 while read -n1 c; do
 echo -n "$c"
 sleep 0.1
 done <<< "$1"
}

echo "                  888 d8b      888                                   "       
echo "                  888 Y8P      888                                   " 
echo "                  888          888                                   "
echo ".d8888b   .d88b.  888 888  .d88888  .d8888b  .d88b.  888d888  .d88b. " 
echo "88K      d88""88b 888 888 d88" 888 d88P"    d88""88b 888P"   d8P  Y8b" 
echo ""Y8888b. 888  888 888 888 888  888 888      888  888 888     88888888"
echo "     X88 Y88..88P 888 888 Y88b 888 Y88b.    Y88..88P 888     Y8b.    " 
echo " 88888P'  "echo"Y88P"echo"  888 888  "echo"Y88888  "echo"Y8888P  "echo"Y88P"echo"  888      "echo"Y8888 "
echo
echo

sleep 3
echo
echo
typeit "Welcome to solidcore, the hardening script for immutable Fedora"
typeit "You are currently running: $detected_variant"

sleep 1
echo
typeit "This script will carry out the following hardening measures:"
typeit "1. Kernel and physical hardening to reduce attack surface"
typeit "2. Hardening of network settings to prevent IP spoofing and protect against various forms of attack"
typeit "3. Hide sensitive kernel and file information from other users and potential attackers"
typeit "4. Improved password policies"
typeit "5. Enabling automatic updates for rpm-ostree and flatpaks"

sleep 1
echo
typeit "This script is open source (GPLv3) and has been tested on Silverblue 38 by the author."
typeit "If you encounter any issues please report them on Github."
echo "https://github.com/solidc0re/solidcore-scripts"
echo
typeit "Hardening MAY reduce your experience of your device and is not suited for everyone."

sleep 2
echo
read -p "Do you want to continue? (Y/n): " grub_response
if [[ "$grub_response" =~ ^[Yy]$ ]]; then

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

# Output default settings to the new script
echo "#!/bin/bash" > /etc/solidcore/defaults.sh
for key in "${!sysctl_settings[@]}"; do
    # Get the existing sysctl value
    existing_value=$(sysctl -n "$key")
    echo "# Current value of $key: $existing_value" >> /etc/solidcore/defaults.sh
    echo "sysctl -w $key=$existing_value" >> /etc/solidcore/defaults.sh
done
chmod +x /etc/solidcore/defaults.sh

# Define an array of files to be backed up
files_to_backup=(
    "/etc/default/grub"
    "/etc/fstab"
    "/etc/rpm-ostreed.conf"
    "/etc/security/limits.conf"
    "/etc/ssh/sshd_config"
    "/etc/systemd/coredump.conf"
    "/etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf"
)

# Loop through the array and create backup copies
for source_file in "${files_to_backup[@]}"; do
    # Check if the source file exists
    if [ -e "$source_file" ]; then
        # Get the filename from the path
        filename=$(basename "$source_file")
        # Construct the backup filename
        backup_file="${source_file}_sc.bak"
        # Copy the source file to the backup file
        cp "$source_file" "$backup_file"
        echo "Backup created: $backup_file"
    fi
done


# === APPLY SYSCTL SETTINGS ===

# Apply new sysctl settings
echo "Applying solidcore sysctl settings."
for key in "${!sysctl_settings[@]}"; do
    sysctl -w "$key=${sysctl_settings[$key]}" > /dev/null
done


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
    *) echo "CPU vendor doesn't match GenuineIntel or AuthenticAMD. CPU Vendor currently recorded as: $cpu_vendor" ;;
esac

# Construct the new GRUB_CMDLINE_LINUX_DEFAULT value
new_cmdline="GRUB_CMDLINE_LINUX_DEFAULT=\"${boot_parameters[*]}\""

# Update the /etc/default/grub file
if grep -q "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub; then
    # If the line already exists, replace it
    sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|$new_cmdline|" /etc/default/grub
    echo "Updated GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub"
else
    # If the line doesn't exist, add it at the end of the file
    echo "$new_cmdline" >> /etc/default/grub
    echo "Added GRUB_CMDLINE_LINUX_DEFAULT to /etc/default/grub"
fi

# Run update-grub to update GRUB configuration
if [[ "$test_mode" == false ]]; then
    if grub2-mkconfig -o /boot/grub2/grub.cfg; then
        echo "GRUB configuration updated."
    else
        echo "Failed to update GRUB configuration."
    fi
else
    echo "Testing. Skipped updating of GRUB configuration."
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

echo "Kernel modules blacklisted."


# === DISABLE SERVICES ===

# High risk and unused services/sockets
services=(
    #abrt-journal-core.service # Not found in F38
    #abrt-oops.service # Fedora crash reporting
    #abrtd.service # Fedora crashing reporting
    avahi-daemon # Recommended by CIS
    geoclue.service # Location service
    httpd # Recommended by CIS
    nfs-server # Recommended by CIS
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
        # Echo a message
        echo "$service disabled and masked."
    else
        echo "$service does not exist. Skipping..."
    fi
done

# === HIDEPID ===

# Add line to /etc/fstab
fstab_line="proc /proc proc nosuid,nodev,noexec,hidepid=2 0 0"
echo "$fstab_line" | tee -a /etc/fstab > /dev/null
systemctl daemon-reload

echo "hidepid enabled for /proc."


# === FILE PERMISSIONS ===

# Hide kernel modules from group and user (only root can access it)
chmod -R go-rwx /usr/lib/modules 2> /dev/null
chmod -R go-rwx /lib/modules 2> /dev/null

echo "Kernel information hidden from everyone, but root."

# Ensure new files are only readable by the user who created them
umask_script="/etc/profile.d/solidcore_umask.sh"

# Create the umask script
echo '#!/bin/bash' | tee "$umask_script" > /dev/null
echo 'umask 0077' | tee -a "$umask_script" > /dev/null

# Make the script executable
chmod +x "$umask_script"

echo "Newly created files now only readable by user that created them."


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
sudo systemctl daemon-reload

echo "Core dumps disabled."


# === PASSWORD POLICIES ===

# Create a custom authselect profile called "solidcore"
authselect create-profile solidcore -b sssd

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
        echo "Lines updated in: $file"
    else
        echo "File not found: $file"
    fi
done

# Apply the custom profile
authselect select custom/solidcore > /dev/nul
echo "Custom password profile 'solidcore' created and applied."


# === LOCK ROOT ===

# Uncomment the PermitRootLogin line in sshd_config, should someone ever enable it on their desktop
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Lock root account
passwd -l root > /dev/null
echo "Root account locked."


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

echo "No insecure repos found in yum repository directory."


# === AUTOMATIC UPDATES ===

# RPM-OSTREE 

# Update the rpm-ostree timer to trigger updates 10 minutes after boot and every 3 hours

timer_dir="/etc/systemd/system/rpm-ostreed-automatic.timer.d"
override_file="$timer_dir/override.conf"

# Check if the override.conf file exists
if [ -f "$override_file" ]; then
    # Remove the original file
    rm "$override_file"
    echo "Original file removed: $override_file"
fi

mkdir -p "$timer_dir"

cat > /etc/systemd/system/rpm-ostreed-automatic.timer.d/override.conf <<EOL
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

# Enable and start the rpm-ostreed-automatic.timer service
systemctl enable rpm-ostreed-automatic.timer > /dev/null
systemctl start rpm-ostreed-automatic.timer

echo "Automatic updates using rpm-ostree are enabled with a frequency of 10 minutes after boot and every 3 hours."

# FLATPAK

# Enable Flathub
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak remote-modify --no-filter --enable flathub

# Change remotes of existing flathub apps
echo "Replacing Fedora flatpaks with Flathub versions"

# Create undo script
echo "#!/bin/bash" > /etc/solidcore/fedora_flatpak.sh
echo "flatpak remote-modify --enable fedora" >> /etc/solidcore/fedora_flatpak.sh

# Get a list of Fedora flatpaks and output install commands
flatpak list --app-runtime=org.fedoraproject.Platform --columns=application | tail -n +2 | while read -r flatpak_name; do
    echo "flatpak install -y --noninteractive --reinstall fedora $flatpak_name" >> /etc/solidcore/fedora_flatpak.sh
done

# Append the disable command for Flathub to the end of fedora_flatpak.sh
echo "flatpak remote-modify --disable flathub" >> /etc/solidcore/fedora_flatpak.sh
chmod +x /etc/solidcore/fedora_flatpak.sh

# Reinstall fedora apps with 
flatpak install -y --noninteractive --reinstall flathub $(flatpak list --app-runtime=org.fedoraproject.Platform --columns=application | tail -n +1 )

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

# Enable and start the Flatpak update timer
systemctl enable flatpak-update.timer > /dev/null
systemctl start flatpak-update.timer

echo "Automatic updates for Flatpak using systemd timer have been enabled."


# === MISC ===

# Mute microphone by default - doesn't work when run as sudo; devise another way of muting the microphone.
#amixer set Capture nocap


# === INSTALLS ===

flatpak install -y flatseal
rpm-ostree install dnscrypt-proxy
echo "Flatseal & dnscrypt-proxy installed."


# === SETUP FIRSTBOOT ===

# Check if solidcore-firstboot.sh exists in the working directory
if [ -e "$PWD/solidcore-firstboot.sh" ]; then
    # Make solidcore-firstboot.sh executable
    chmod +x solidcore-firstboot.sh
    # Create the directory if it doesn't exist
    mkdir -p /etc/solidcore
    # Move the file to /etc/solidcore/
    mv "solidcore-firstboot.sh" "/etc/solidcore/"
    echo "solidcore-firstboot.sh moved to /etc/solidcore/"
# Create a xdg autostart file
cat > /etc/xdg/autostart/solidcore-firstboot.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Solidcore Script to Run on First Boot
Exec=sudo /etc/solidcore/solidcore-firstboot.sh
Terminal=true
Icon=utilities-terminal
EOF
else
    echo "solidcore-firstboot.sh does not exist in the current directory. Aborting."
    exit 1
fi


# === MAKE UNINSTALL EXECUTABLE ===

if [ -e "$PWD/solidcore-uninstall.sh" ]; then
    # Make solidcore-uninstall.sh executable
    chmod +x solidcore-uninstall.sh
else
    echo "solidcore-uninstall.sh does not existing the current director. Aborting."
    exit 1
fi

# === REBOOT ===
if [[ "$test_mode" == false ]]; then
    for i in {5..1}; do
        echo -ne "\rRebooting in $i seconds..."
        sleep 1
    done
    echo -e "\rRebooting now!"
    reboot
else
    echo "Script completed - check the changes made by the script"
fi

# === CHICKEN ===
# Pressed no to original question?
else
    echo "Aborting."
    exit 0
fi
