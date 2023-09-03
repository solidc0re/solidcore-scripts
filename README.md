# solidcore-scripts
### Hardening scripts for immutable Fedora.

**:cupid: Love [Fedora](https://fedoraproject.org/)?**

**:sparkling_heart: Love the immutable desktops?**

**:hushed: Thought you were safe?**

Whilst it is true that a read-only (immutable) filesystem during run-time does reduce a lot of attack surface exploited by malware, security depends on much more than that.

- **What if someone gains physical access to your device?**
- **What is someone else who uses your computer downloads malware?**
- **What if you are the target of malicious network activity?** ... You get the picture.

These are just some of the issues that solidcore hardening aims to protect against.

# Aims
**This project aims to protect immutable Fedora variants against a variety of attack vectors by:**
- **Securing the bootloader**
- **Hardening the kernel**
- **Locking down root and implementing stronger password policies**
- **Blocking malicious domains**
- **Disabling all unused ports and interfaces**
- **Improving the firewall settings**
- :fire: ***... plus more!!*** :fire:

# Current features
**Despite the low version number of v0.1.1, this script implements some serious hardening.**

What follows is a long list of the current features:

- Guided user interface :heavy_check_mark:
- Auto-generate backups of important config files :heavy_check_mark:
- Sysctl kernel, network and userspace hardening :heavy_check_mark:
- Hardened GRUB boot parameters :heavy_check_mark:
- Kernel module blacklist :heavy_check_mark:
- High risk and unused services disabled and masked :heavy_check_mark:
- Process information hidden from users :heavy_check_mark:
- Kernel information hidden from users :heavy_check_mark:
- New files only viewable to owner/creator :heavy_check_mark:
- Core dumps disabled (stops sensitive information about the system being available) :heavy_check_mark:
- Improved password policies :heavy_check_mark:
- Root account locked :heavy_check_mark:
- Firewalld zone set to drop (drops all incoming connections) :heavy_check_mark:
- Check yum repos for insecure HTTP URLs :heavy_check_mark:
- Automatic updates for rpm-ostree and flatpaks :heavy_check_mark:
- Fedora flatpaks replaced with Flathub flatpaks :heavy_check_mark:
- Mute microphone by default on login :heavy_check_mark:
- Flatseal installed :heavy_check_mark:
- Firstboot script installed to ensure:
  - New password set :heavy_check_mark:
  - GRUB password set (optional, but recommended) :heavy_check_mark:
  - Wireless technologies blocked (optional) :heavy_check_mark:
  - Unused ports are disabled and blacklisted :heavy_check_mark:
  - USBGuard installed (if required) :heavy_check_mark:
  - Enable hardware key support (optional) :heavy_check_mark:
- [DNSCrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) installed (no need to trust your ISP, nor your VPN) :heavy_check_mark:
- DNS blocklists added :heavy_check_mark:
- Updates scheduled for dnscrypt-proxy and DNS blocklists :heavy_check_mark:
- Uninstall file (mostly working)

**Tested on Fedora Silverblue 38.**

# Planned features and future goals
The long-term goal (probably for v1.0) is to have the hardening provided by this script work both client-side - i.e. manual running of the script on any existing immutable Fedora system - and server-side, so people can carry out an rpm-ostree rebase to a pre-hardened and constantly updated system.

In the meantime, there's plenty of work to do. Including the following, in no particular order:
- create testing VMs of all official immutable Fedora variants
- create solidcore aliases for common post-install actions
- develop the `-test` flag further for more verbosity
- align as much as immutable Fedora will allow with the Center for Internet Security's RHEL 9 Workstation Level 1 & Level 2 benchmark
- research and improve sysctl and bootloader hardening
- install and sign hardened kernel (removing any currently implemented kernel hardening)
- implement pam.d overwrites with stronger defaults
- implement improvements to the USBGuard config
- progress on getting the hardened malloc to work
- create scripts to audit all relevant settings on new versions of Fedora to make keeping it up-to-date easier
- research and possibly implement clam-tk and AIDE
- research anti-forensic tools
- improve user interactions
- set up full installation of hardware keys, i.e. creation of U2F pam module key and required modification to solidcore pam profile
- develop the `-server` flag further to eliminate all user interaction
- write more documentation/start a Github wiki
- implement conditional conf_msg and error reporting
- add SELinux enforcing check
- add blank password check for all users, or have all users update their password on next login
- add mitigations check
- review and potentially implement chronyd (NTP) [improvements](https://chrony-project.org/faq.html#_how_can_i_make_the_system_clock_more_secure)
- `/etc/security/access.conf` test disallowing console logins to non-wheel users
- further harden SSHD in case someone activates it

For the next release:
- [x] create testing branch for the sake of your sanity and mine
- [x] get minisign to work properly (dnscrypt-proxy install and updates)
- user-testing and implement feedback
- test uninstall process thoroughly

# Instructions
> [!NOTE]
> **Currently in alpha stage.** Only install for testing purposes or if you're really keen. The uninstall script is not fully tested, but all changes instigated by the script are reversible.

## Installation

### Pre-install recommendations

1. It is strongly recommended to install your favourite immutable Fedora variant on an encrypted drive. Drive encryption is best done during the installation process of the OS, [although may be possible after](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/encrypting-block-devices-using-luks_security-hardening#encrypting-existing-data-on-a-block-device-using-luks2_encrypting-block-devices-using-luks). See the [Fedora docs](https://docs.fedoraproject.org/en-US/quick-docs/encrypting-drives-using-LUKS/#_creating_encrypted_block_devices_in_anaconda) for information on how to encrypt the drive during the installation process.

1. If you haven't added a password to your BIOS yet, either, then please do so and ensure that - in the boot order section - your device boots from the encrypted drive before any USB drives. Please also ensure that SecureBoot is enabled.

### Installing

To install the solidcore-scripts, type in the following command and follow the on-screen instructions:
```
wget https://raw.githubusercontent.com/solidc0re/solidcore-scripts/main/solidcore-install.sh && sudo bash solidcore-install.sh
```


## Upgrading

Uninstall first, then re-install, just to be safe.

Uninstall:
```
sudo bash /etc/soldicore/uninstall
```

Re-install:
```
wget https://raw.githubusercontent.com/solidc0re/solidcore-scripts/main/solidcore-install.sh && sudo bash solidcore-install.sh
```


## Uninstalling
Uninstalling reverts all changed system settings to how they previously were, along with uninstalling any solidcore-installed packages.
```
sudo bash /etc/soldicore/uninstall
```


# Post-install information
Congratulations! You have hardened your immutable Fedora installation.

Your GRUB username is 'root' - you will need this if you want to change your GRUB entries. The password is what you set it as during the firstboot script.

Most computer security threats come from online sources. It is therefore strongly recommended that you install a more secure browser, such as [Brave](https://brave.com/) (Chrome-based, boo!) or [Librewolf](https://librewolf.net/) (pre-hardened Firefox).

```
flatpak install io.gitlab.librewolf-community
```

If you are a [Mullvad](https://mullvad.net/) user then [Mullvad browser](https://flathub.org/apps/net.mullvad.MullvadBrowser) is by far the best browser option available, unless you want to use [Tor](https://flathub.org/apps/com.github.micahflee.torbrowser-launcher).

Your system will automatically update the following:
- dnscrypt-proxy and DNS blocklists, 20 seconds after boot and every 24 hours
- rpm-ostree, 10 minutes after boot and every 3 hours
- Flatpak apps, 20 minutes after boot and every 3 hours 10 minutes

If USBGuard was installed when running solidcore-scripts, then I recommend reviewing the allowed devices and blocking any you don't use (such as fingerprint readers):

```
sudo usbguard list-devices
```
```
sudo usbguard block-device <device number>
```

Please report any issues and suggested improvements on [this Github page](https://github.com/solidc0re/solidcore-scripts/issues).

# 'How to' guides

<details>
<summary>How to: add a domain to the DNS allowlist</summary>

### How to: add a domain to the DNS allowlist

If you're happy with the blocklist set up but there's still the odd domain that you want to allow that's currently being blocked, then the allowlist is for you. The allowlist is located here: '/usr/local/sbin/dnscrypt-proxy/domains-allowlist.txt'.

To edit:
```
sudo nano /usr/local/sbin/dnscrypt-proxy/domains-allowlist.txt
```
Simply add a domain, such as 'github.com', with each domain on a new line. Once changes have been made to 'domains-allowlist.txt', run the following command to apply them:
```
sudo systemctl start dnscrypt-proxy-update
```

Refer to the https://github.com/DNSCrypt/dnscrypt-proxy/wiki if you need further assistance.
</details>

<details>
<summary>How to: change the DNS blocklists</summary>

### How to: change the DNS blocklists
  
The blocklists are stored in '/usr/local/sbin/dnscrypt-proxy/domains-blocklist.conf'. To edit:
```
sudo nano /usr/local/sbin/dnscrypt-proxy/domains-blocklist.conf
```

Once changes have been made to 'domains-blocklist.conf', run the following command to apply them:
```
sudo systemctl start dnscrypt-proxy-update
```

Refer to https://github.com/DNSCrypt/dnscrypt-proxy/wiki if you need further assistance.
</details>

<details>
<summary>How to: unblock bluetooth</summary>

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
</details>

<details>
<summary>How to: unblock Firewire</summary>

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
</details>

<details>
<summary>How to: unblock Thunderbolt</summary>

### How to: unblock Thunderbolt
  
```
sudo sed -i '/blacklist thunderbolt/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:

```
sudo boltctl list
```

Then use:
```
sudo boltctl enable <domain>
```
... for the Thunderbolt domain you wish to enable.
</details>

<details>
<summary>How to: unblock USB</summary>

### How to: unblock USB

This is for those who blacklisted the USB kernel module - NOT FOR THOSE WHO INSTALLED USBGUARD. To unblock the USB modules:
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
</details>

<details>
<summary>How to: allow/unblock a USB device using USBGuard</summary>
  
### How to: allow/unblock a USB device using USBGuard

If you notified solidcore-script that you use USB ports, it will have installed USBGuard to protect these ports. This means that all unknown USB devices will not be accessible. To whitelist devices:
```
sudo usbguard list-devices
```
```
sudo usbguard allow-device <device number>
```
</details>

<details>
<summary>How to: block a USB device using USBGuard</summary>
  
### How to: block a USB device using USBGuard

If you notified solidcore-script that you use USB ports, it will have installed USBGuard to protect these ports. This means that all unknown USB devices will not be accessible. To whitelist devices:
```
sudo usbguard list-devices
```
```
sudo usbguard block-device <device number>
```
</details>

<details>
<summary>How to: unblock webcam</summary>
  
### How to: unblock webcam
  
First:
```
sudo sed -i '/blacklist uvcvideo/s/^/#/' /etc/modprobe.d/solidcore-blacklist.conf
```

Then reboot. After reboot:
```
sudo insmod uvcvideo
```
</details>

<details>
<summary>How to: unblock Wi-Fi</summary>

### How to: unblock Wi-Fi
  
```
rfkill unblock wifi
```
</details>

<details>
<summary>How to: stop microphone being muted on login</summary>

### How to: stop microphone being muted on login
  
```
sudo rm /etc/xdg/autostart/solidcore-mute-mic.desktop
```
</details>

# Comments

The focus of this project is OS hardening, not changing the default Fedora software choices.

That said, some opinionated choices had to be made. These include the installation of dnscrypt-proxy, the DNS blocklists used, keeping IPv6 active and switiching all Fedora project flatpaks to Flathub source flatpaks. If you don't agree with these then feel free to contact me, donwload the scripts and manually undo the changes, or fork the repo and implement your own preferences.

# Acknowledgements
This project is made possible by the diligent and forward-thinking work of the Fedora and RedHat developers and community. A special shout out to the CoreOS and rpm-ostree developers for their excellent work.

Many of the hardening improvements implemented by the solidcore-scripts are recommendations from these sources:
- https://madaidans-insecurities.github.io/guides/linux-hardening.html
- https://wiki.archlinux.org/title/Security
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
- https://www.cisecurity.org/benchmark/red_hat_linux
- https://github.com/ComplianceAsCode/content
- https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
- https://github.com/a13xp0p0v/kconfig-hardened-check/

# Introductory resources
If you're relatively new to the infosec (information security) world, then the following resources come recommended:

🎥 **YouTube channels**
- [NBTV, with Naomi Brockwell](https://www.youtube.com/@NaomiBrockwellTV)
- [Side of Burritos](https://www.youtube.com/@sideofburritos)
- [The New Oil](https://www.youtube.com/channel/UCH5DsMZAgdx5Fkk9wwMNwCA)
- [Techlore](https://www.youtube.com/@techlore)

🎧 **Podcasts**
- [Malwarebytes Podcast](https://www.malwarebytes.com/blog/category/podcast)
- [Surveillance Report](https://surveillancereport.tech/)

👀 **Websites & guides**
- [The New Oil](https://thenewoil.org/)
- [National Cyber Security Centre (UK)](https://www.ncsc.gov.uk/section/advice-guidance/all-topics)
- [Privacy Tools](https://www.privacytools.io/)
