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

# Sudo check

# Check if the script is being run with sudo privileges
if [ "$EUID" -ne 0 ]; then
    echo "This script requires sudo privileges. Please run it with 'sudo' using 'sudo ./solidcore-install.sh"
    exit 1
fi

# Variant check

# Check immutable variant
# Define an array of immutable Fedora variants
declare -a fedora_variants=("Silverblue" "Kinoite" "Sericea" "Vauxite" "Onyx")

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
    echo "Detected immutable Fedora variant: $detected_variant"
else
    echo "No supported immutable Fedora variant detected."
    exit 1
fi

# === SYSCTL PARAMETERS ===

# Array of sysctl commands and their new settings
declare -A sysctl_settings=(
    # KERNEL
    ["kernel.kptr_restrict"]="2" # Mitigate kernel pointer leaks
    ["kernel.dmesg_restrict"]="1" # Restrict kernel log
    ["kernel.printk"]="3 3 3 3" # Stop printing kernel log on boot
    ["kernel.unprivileged_bpf_disabled"]="1" # Restrict eBPF
    ["net.core.bpf_jit_harden"]="2"
    ["dev.tty.ldisc_autoload"]="0" # Restrict loading TTY line disciplines
    ["kernel.kexec_load_disabled"]="1" # Disable kexec
    ["kernel.sysrq"]="0" # Disable SysRq
    ["kernel.perf_event_paranoid"]="3" # Restrict usage of performance events
    # NETWORK
    ["net.ipv4.tcp_syncookies"]="1" # Protect against SYN flood attacks
    ["net.ipv4.tcp_rfc1337"]="1" # Protect against time-wait assassination
    ["net.ipv4.conf.all.rp_filter"]="1" ] # Protect against IP spoofing
    ["net.ipv4.conf.default.rp_filter"]="1"
    ["net.ipv4.conf.all.accept_redirects"]="0" # Disable ICMP redirect acceptance
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.secure_redirects"]="0"
    ["net.ipv4.conf.default.secure_redirects"]="0"
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
    ["net.ipv4.icmp_echo_ignore_all"]="1" # Prevent smurf attacks and clock fingerprinting
    ["net.ipv6.conf.all.accept_ra"]="0" # Disable IPv6 router advertisements
    ["net.ipv6.conf.default.accept_ra"]="0"
    ["net.ipv4.tcp_sack"]="0" # Disable TCP SACK
    ["net.ipv4.tcp_dsack"]="0"
    ["net.ipv4.tcp_fack"]="0"
    ["net.ipv4.tcp_timestamps"]="0" # Disable TCP timestamps
    ["net.ipv6.conf.all.use_tempaddr"]="2" # Generate random IPv6 addresses
    ["net.ipv6.conf.default.use_tempaddr"]="2"
    # USERSPACE
    ["kernel.yama.ptrace_scope"]="2" # Restrict ptrace
    ["vm.mmap_rnd_bits"]="32" # Increase mmap ALSR entropy
    ["vm.mmap_rnd_compat_bits"]="16"
    ["fs.protected_fifos"]="2" # Prevent creating files in potential attacker-controlled directories
    ["fs.protected_regular"]="2"
)

# === BACKUPS & RESTORE FILE ===

# Create the directory if it doesn't exist
mkdir -p /etc/solidcore

# Output default settings to the new script
echo "#!/bin/bash" > /etc/solidcore/defaults.sh
for key in "${!sysctl_settings[@]}"; do
    echo "sysctl -w $key=${sysctl_settings[$key]}" >> /etc/solidcore/defaults.sh
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
    "/etc/systemd/system/systemd-logind.service.d/hidepid.conf"
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
for key in "${!sysctl_settings[@]}"; do
    echo "Setting $key to new value: ${sysctl_settings[$key]}"
    sysctl -w "$key=${sysctl_settings[$key]}"
done


# === BOOTLOADER SETTINGS ===

# Check CPU vendor using lscpu
cpu_vendor=$(lscpu | grep Vendor | awk '{print $2}')

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
if [ "$cpu_vendor" == "GenuineIntel" ]; then
    boot_parameters+=("intel_iommu=on")
elif [ "$cpu_vendor" == "AuthenticAMD" ]; then
    boot_parameters+=("amd_iommu=on")
fi

# Construct the new GRUB_CMDLINE_LINUX_DEFAULT value
new_cmdline="GRUB_CMDLINE_LINUX_DEFAULT=\"${boot_parameters[*]}\""

# Update the /etc/default/grub file
if sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|$new_cmdline|" /etc/default/grub; then
    echo "Updated GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub"
    
    # Run update-grub to update GRUB configuration
    if grub2-mkconfig -o /boot/grub2/grub.cfg; then
        echo "GRUB configuration updated."
    else
        echo "Failed to update GRUB configuration."
    fi
else
    echo "Failed to update GRUB_CMDLINE_LINUX_DEFAULT."
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
for module in "${modules_to_blacklist[@]}"; do
    echo "blacklist $module" | tee -a "$blacklist_file" > /dev/null
done

# Update initramfs
update-initramfs -u

echo "Kernel modules blacklisted."


# === DISABLE SERVICES ===

# High risk and unused services/sockets
services=(
    abrt-journal-core.service # Fedora crash reporting
    abrt-oops.service # Fedora crash reporting
    abrtd.service # Fedora crashing reporting
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
    # Stop the service/socket
    systemctl stop "$service"
    
    # Disable the service/socket
    systemctl disable "$service"

    # Mask service/socket
    systemctl --now mask "$service"

    # Echo a message
    echo "$service disabled and masked."
done


# === HIDEPID ===

# Add line to /etc/fstab
fstab_line="proc /proc proc nosuid,nodev,noexec,hidepid=2,gid=proc 0 0"
echo "$fstab_line" | tee -a /etc/fstab > /dev/null
systemctl daemon-reload

# Create systemd-logind hidepid.conf
hidepid_conf="/etc/systemd/system/systemd-logind.service.d/hidepid.conf"
mkdir -p "$(dirname $hidepid_conf)"
echo "[Service]" | tee "$hidepid_conf" > /dev/null
echo "SupplementaryGroups=proc" | tee -a "$hidepid_conf" > /dev/null

echo "Configuration added to /etc/fstab and $hidepid_conf."


# === FILE PERMISSIONS ===

# Hide kernel modules from group and user (only root can access it)
chmod -R go-rwx /usr/lib/modules
chmod -R go-rwx /lib/modules

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

# Add a line to disable core dumps in limits.conf
echo "* hard core 0" | tee -a /etc/security/limits.conf > /dev/null

# Update the coredump.conf file
echo "[Coredump]" | tee /etc/systemd/coredump.conf
echo "Storage=none" | tee -a /etc/systemd/coredump.conf
echo "ProcessSizeMax=0" | tee -a /etc/systemd/coredump.conf
echo "ExternalSizeMax=0" | tee -a /etc/systemd/coredump.conf

# restart coredump service
systemctl restart systemd-coredump

echo "Core dumps disabled."


# === PASSWORD POLICIES ===

# Enforce strongest cryptographic policy available in Fedora
update-crypto-policies --set FUTURE
echo "Strongest cryptographic policies applied."

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
   	sed -i "/pam_quality.so/ /s/$/ minlen=12/" "$file"
        echo "Lines updated in: $file"
    else
        echo "File not found: $file"
    fi
done

# Apply the custom profile
authselect select custom/solidcore
echo "Custom password profile 'solidcore' created and applied."


# === LOCK ROOT ===

# Uncomment the PermitRootLogin line in sshd_config, should someone ever enable it on their desktop
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Lock root account
passwd -l root


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

# Update the rpm-ostree timer to trigger updates 15 minutes after boot and every 3 hours
echo "Changing rpm-ostreed-automatic.timer to update 15 minutes after boot and every 3 hours..."

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
Description=Run rpm-ostree updates every 3 hours and 10 minutes after boot

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
systemctl enable rpm-ostreed-automatic.timer
systemctl start rpm-ostreed-automatic.timer

echo "Automatic updates using rpm-ostree are enabled with a frequency of 10 minutes after boot and every 3 hours."

# FLATPAK

# Enable Flathub
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak remote-modify --no-filter --enable flathub

# Change remotes of existing flathub apps
flatpak install --reinstall flathub $(flatpak list --app-runtime=org.fedoraproject.Platform --columns=application | tail -n +1 )

# Remove Fedora flatpak repo
flatpak remote-delete fedora

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
Description=Run Flatpak updates every 3 hours and 10 minutes and 20 minutes after boot

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
systemctl enable flatpak-update.timer
systemctl start flatpak-update.timer

echo "Automatic updates for Flatpak using systemd timer have been enabled."


# === MISC ===

# Mute microphone by default
amixer set Capture nocap


# === INSTALLS ===

flatpak install flatseal
rpm-ostree install dnscrypt-proxy
echo "Flatseal & dnscrypt-proxy installed."


# === SETUP FIRSTBOOT ===


# Check if solidcore-firstboot.sh exists in the current directory
if [ -e "solidcore-firstboot.sh" ]; then
	# Make solidcore-firstboot.sh executable
	chmod +x solidcore-firstboot.sh
    # Create the directory if it doesn't exist
	mkdir -p /etc/solidcore
    # Move the file to /etc/solidcore/
    mv "solidcore-firstboot.sh" "/etc/solidcore/"
    echo "solidcore-firstboot.sh moved to /etc/solidcore/"
    # Create a systemd service unit
    service_unit_file="/etc/systemd/system/solidcore-first-boot.service"
        cat > "$service_unit_file" <<EOF
        [Unit]
        Description=Solidcore Script to Run on First Boot
    
        [Service]
        Type=oneshot
        ExecStart=sudo /etc/solidcore/solidcore-firstboot.sh
    
        [Install]
        WantedBy=multi-user.target
        EOF
    
    # Make the service unit file readable only by root
    chmod 600 "$service_unit_file"

    # Enable and start the service
    systemctl enable solidcore-first-boot.service
    systemctl start solidcore-first-boot.service
else
    echo "solidcore-firstboot.sh does not exist in the current directory."
    exit 1
fi


# === REBOOT ===

for i in {5..1}; do
    echo -ne "\rRebooting in $i seconds..."
    sleep 1
done
echo -e "\rRebooting now!"
reboot
