# solidcore-scripts
Hardening scripts for immutable Fedora.

Work in progress... *Not currently ready for home use.*

- solidcore-install.sh is currently operational and functioning
- solidcore-firstboot.sh is currently operational and functioning
- solidcore-uninstall.sh to be tested once firstboot.sh finished

## Current features

- Guided user interface :white_check_mark:
- Auto-generate backups of important config files :white_check_mark:
- Sysctl kernel, network and userspace hardening :white_check_mark:
- Hardened GRUB boot parameters :white_check_mark:
- Kernel module blacklist :white_check_mark: 
- High risk and unused services disabled and masked :white_check_mark:
- Process information hidden from users :white_check_mark:
- Kernel information hidden from users :white_check_mark:
- New files only viewable to owner/creator :white_check_mark:
- Core dumps disabled (stops sensitive information about the system being available) :white_check_mark:
- Improved password policies :white_check_mark:
- Root account locked :white_check_mark:
- Firewalld zone set to drop (drops all incoming connections) :white_check_mark:
- Check yum repos for insecure HTTP URLs :white_check_mark:
- Automatic updates for rpm-ostree and flatpaks :white_check_mark:
- Fedora flatpaks replaced with Flathub flatpaks :white_check_mark:
- Mute microphone by default on login :white_check_mark:
- Flatseal installed :white_check_mark:
- DNSCrypt-proxy installed :white_check_mark:
- DNS blocklists added :white_check_mark:
- Firstboot script installed to ensure: new password set, GRUB password set, unused ports are disabled and blacklisted, USBGuard installed (if required) :white_check_mark:
- Uninstall file (mostly working, not tested recently)

## Planned features and future goals
The long-term goal (probably for v1.0) is to have the hardening provided by this script work on both the client-side - i.e. manual running of the script on any existing immutable Fedora system - and server-side, so people can carry out an rpm-ostree rebase to a pre-hardened and constantly updated system.

In the meantime, there's plenty of work to do. Including the following, in no particular order:
- start a testing branch
- create testing VMs of all official immutable Fedora variants
- develop the `-test` flag further for more verbosity
- align as much as immutable Fedora will allow with CIS RHEL 9 Workstation Level 1 & Level 2 hardening
- research and improve sysctl and bootloader hardening
- install and sign hardened kernel (removing any currently implemented kernel hardening)
- implement pam.d overwrites with stronger defaults
- implement improvements to the USBGUard config
- progress on getting the hardened malloc to work
- create scripts to audit all relevant settings on new versions of Fedora to make keeping it up-to-date easier
- research anti-forensic tools
- improve user interations
- develop the `-server` flag further to eliminate all user interaction
- write more documentation/start a Github wiki

## Installation instructions
Coming soon.

## Post-install information
Coming soon.

## Acknowledgements
This project is made possible by the diligent and inspiring work of the Fedora and RedHat developers and community. A special shout out to the CoreOS and rpm-ostree developers for their excellent work.

Many of the hardening improvements implemented by the solidcore-scripts are recommendations from these excellent sources:
- https://madaidans-insecurities.github.io/guides/linux-hardening.html
- https://wiki.archlinux.org/title/Security
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
- https://www.cisecurity.org/benchmark/red_hat_linux
- https://github.com/ComplianceAsCode/content
- https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
- https://github.com/a13xp0p0v/kconfig-hardened-check/
