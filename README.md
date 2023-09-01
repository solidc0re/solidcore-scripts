# solidcore-scripts
### Hardening scripts for immutable Fedora.

**:cupid: Love Fedora?**

**:sparkling_heart: Love the immitable spins?**

**:hushed: Thought you were safe?**


**... So did I until I started this project :scream:**


**This project aims to protect against a variety of attack vectors by:**
- Securing the bootloader
- Hardening the kernel
- Locking down root and implementing strong password policies
- Encrypting DNS (DNSCrypt protocol) and blocking malicious domains
- Disabling all unused ports and interfaces
- Improved firewall settings
- ... plus more!! :fire:

> [!WARNING]
> Work in progress... *Not currently ready for home use.*

### Status

- solidcore-install.sh is currently operational and functioning
- solidcore-firstboot.sh is currently operational and functioning
- solidcore-uninstall.sh currently undergoing active testing


## Current features
Despite the low version number of v0.1, this script implements some serious hardening.

- [x] Guided user interface
- [x] Auto-generate backups of important config files
- [x] Sysctl kernel, network and userspace hardening
- [x] Hardened GRUB boot parameters
- [x] Kernel module blacklist 
- [x] High risk and unused services disabled and masked
- [x] Process information hidden from users
- [x] Kernel information hidden from users
- [x] New files only viewable to owner/creator
- [x] Core dumps disabled (stops sensitive information about the system being available)
- [x] Improved password policies
- [x] Root account locked
- [x] Firewalld zone set to drop (drops all incoming connections)
- [x] Check yum repos for insecure HTTP URLs
- [x] Automatic updates for rpm-ostree and flatpaks
- [x] Fedora flatpaks replaced with Flathub flatpaks
- [x] Mute microphone by default on login
- [x] Flatseal installed
- [x] DNSCrypt-proxy installed
- [x] DNS blocklists added
- [x] Firstboot script installed to ensure: new password set, GRUB password set, unused ports are disabled and blacklisted, USBGuard installed (if required)
- [ ] Uninstall file (mostly working, not tested recently)

> [!NOTE]
> Tested on Fedora Silverblue 38.

## Planned features and future goals
The long-term goal (probably for v1.0) is to have the hardening provided by this script work on both client-side - i.e. manual running of the script on any existing immutable Fedora system - and server-side, so people can carry out an rpm-ostree rebase to a pre-hardened and constantly updated system.

In the meantime, there's plenty of work to do. Including the following, in no particular order:
- start a testing branch
- create testing VMs of all official immutable Fedora variants
- create solidcore aliases for common post-install actions
- develop the `-test` flag further for more verbosity
- align as much as immutable Fedora will allow with CIS RHEL 9 Workstation Level 1 & Level 2 hardening
- research and improve sysctl and bootloader hardening
- install and sign hardened kernel (removing any currently implemented kernel hardening)
- implement pam.d overwrites with stronger defaults
- add check for users with blank passwords
- implement improvements to the USBGUard config
- progress on getting the hardened malloc to work
- create scripts to audit all relevant settings on new versions of Fedora to make keeping it up-to-date easier
- research and possibly implement clam-tk and AID
- research anti-forensic tools
- improve user interations
- develop the `-server` flag further to eliminate all user interaction
- write more documentation/start a Github wiki

## Installation
It is strongly recommended to install your favourite immutable Fedora variant on an encrypted drive. This option is only possible during the installation process of the OS. See the [Fedora docs](https://docs.fedoraproject.org/en-US/quick-docs/encrypting-drives-using-LUKS/#_creating_encrypted_block_devices_in_anaconda) for more info.

To install the solidcore-scripts:
```
wget https://raw.githubusercontent.com/solidc0re/solidcore-scripts/main/solidcore-install.sh | sudo bash solidcore-install.sh
```

Then follow the on-screen instructions.

## Upgrading

Uninstall first, then re-install, just to be safe.

Uninstall:
```
sudo bash /etc/soldicore/uninstall
```

Re-install:
```
wget https://raw.githubusercontent.com/solidc0re/solidcore-scripts/main/solidcore-install.sh | sudo bash solidcore-install.sh
```


## Uninstalling
Uninstalling reverts all changed system settings to how they previously were, along with uninstalling any solidcore-installed packages.
```
sudo bash /etc/soldicore/uninstall
```


## Post-install information
Congratulations! You have hardened your immutable Fedora installation.

Your GRUB username is 'root' - you will need this if you want to change your GRUB entries. The password is what you set it as during the firstboot script.

Most cybersecurity threats come from online sources. It is therefore strongly recommended that you install a more secure browser from Flathub, such as Brave (Chrome-based, boo!) or Librewolf (pre-hardened Firefox).

```
flatpak install librewolf
```

If you are a [Mullvad](https://mullvad.net/) user then [Mullvad browser](https://flathub.org/apps/net.mullvad.MullvadBrowser) is by far the best browser option available, unless you want to use [Tor](https://flathub.org/apps/com.github.micahflee.torbrowser-launcher).

Your system will automatically update the following:
- dnscrypt-proxy and DNS blocklists, 20 seconds after boot and every 24 hours
- rpm-ostree, 10 minutes after boot and every 3 hours
- flatpak apps, 20 minutes after boot and every 3 hours 10 minutes

Please report any issues and suggested improvements on [this Github page](https://github.com/solidc0re/solidcore-scripts/issues).

<details>
<summary>How to: whitelist a USB device</summary>
If you notified the script that you use USB ports, it will have installed USBGuard to protect these ports. This means that all unknown USB devices will not be accessible.


To whitelist devices:
```
sudo usbguard list-devices
```
```
sudo usbguard allow-device <device number>
```
</details>

### How to: add a domain to the DNS allowlist
If you're happy with the blocklist set up but there's still the odd domain that you want to allow that's currently being blocked, then the allowlist is for you.

The allowlist is located here: /usr/local/sbin/dnscrypt-proxy/domains-allowlist.txt

To edit:
```
sudo nano /usr/local/sbin/dnscrypt-proxy/domains-allowlist.txt
```

Simply add a domain, such as `github.com`, with each domain on a new line.

Once changes have been made to domains-allowlist.txt, run the following command to apply them:
```
sudo systemctl start dnscrypt-proxy-update
```

Refer to the (dnscrypt-proxy wiki)[https://github.com/DNSCrypt/dnscrypt-proxy/wiki] if you need further assistance.

### How to: change the DNS blocklists
The blocklists are stored in /usr/local/sbin/dnscrypt-proxy/domains-blocklist.conf.

To edit:
```
sudo nano /usr/local/sbin/dnscrypt-proxy/domains-blocklist.conf
```

Once changes have been made to domains-blocklist.conf, run the following command to apply them:
```
sudo systemctl start dnscrypt-proxy-update
```

Refer to the (dnscrypt-proxy wiki)[https://github.com/DNSCrypt/dnscrypt-proxy/wiki] if you need further assistance.

### How to: unblock bluetooth
First:
```
sudo sed -i '/blacklist bluetooth/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```
```
sudo sed -i '/blacklist btusb/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:
```
rkfill unblock bluetooth
```
```
sudo systemctl unmask bluetooth.service
```
```
sudo systemctl enable --now bluetooth.service
```

### How to: unblock Firewire
First:
```
sudo sed -i '/blacklist firewire-core/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```
```
sudo sed -i '/blacklist ohcil394/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```
```
sudo sed -i '/blacklist sbp2/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:
```
sudo insmod firewire_core ohcil394 sbp2
```

### How to: unblock Thunderbolt
```
sudo sed -i '/blacklist thunderbolt/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:
```
sudo boltctl list
```

Then use ```
sudo boltctl enable <domain>
``` for the Thunderbolt domain you wish to enable.

### How to: unblock USB
First:
```
sudo sed -i '/blacklist usbcore/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```
```
sudo sed -i '/blacklist usb_storage/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:
```
sudo insmod usbcore usb_storage
```

### How to: unblock webcam
First:
```
sudo sed -i '/blacklist uvcvideo/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:
```
sudo insmod uvcvideo
```

### How to: unblock Wi-Fi
```
rfkill unblock wifi
```

### How to: stop mic being muted on login
```
sudo rm /etc/xdg/autostart/solidcore-mute-mic.desktop
```

## Acknowledgements
This project is made possible by the diligent and forward-thinking work of the Fedora and RedHat developers and community. A special shout out to the CoreOS and rpm-ostree developers for their excellent work.

Many of the hardening improvements implemented by the solidcore-scripts are recommendations from these sources:
- https://madaidans-insecurities.github.io/guides/linux-hardening.html
- https://wiki.archlinux.org/title/Security
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
- https://www.cisecurity.org/benchmark/red_hat_linux
- https://github.com/ComplianceAsCode/content
- https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
- https://github.com/a13xp0p0v/kconfig-hardened-check/
