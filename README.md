# solidcore-scripts
Hardening scripts for immutable Fedora

Work in progress... *Not currently ready for home use.*

solidcore-install.sh is currently operational and functioning
solidcore-firstboot.sh still needs work
solidcore-uninstall.sh to be tested once firstboot.sh finished

To do
- test dnscrypt-proxy and update settings
- test firstboot script
- tighten user interaction, currently y/n questions can fail on incorrect input
- review sysctl hardening (not needed if we can get server-side signing of hardened kernel to work)
- implement pam.d overwrites with stronger defaults (to meet CIS requirements)
- review additional CIS recommendations and update scripts further
- create scripts to audit all relevant settings on new versions of Fedora

## Current features

:white_check_mark: Cool interface

:white_check_mark: Auto-generate backups of important config files

:white_check_mark: Sysctl kernel, network and userspace hardening

:white_check_mark: Hardened GRUB boot parameters

:white_check_mark: Kernel module blacklist

:white_check_mark: High risk and unused services disabled and masked

:white_check_mark: Process information hidden from users

:white_check_mark: Kernel information hidden from users

:white_check_mark: New files only viewable to owner/creator

:white_check_mark: Core dumps disabled (stops sensitive information about the system being available)

:white_check_mark: Improved password policies

:white_check_mark: Root account locked

:white_check_mark: Firewalld zone set to drop (drops all incoming connections)

:white_check_mark: Check yum repos for insecure HTTP URLs

:white_check_mark: Automatic updates for rpm-ostree and flatpaks (10 - 20 mins after boot, then every 3 hours)

:white_check_mark: Fedora flatpaks replaced with Flathub flatpaks

:white_check_mark: Mute microphone by default on login

:white_check_mark: Flatseal installed

:white_check_mark: DNSCrypt-proxy installed

:white_check_mark: Firstboot script installed to ensure:
- New password set
- GRUB password set
- Unused ports are disabled and blacklisted
- USBGuard installed

:white_check_mark: Uninstall file (mostly working, not tested recently)

## Resources
Resources used in the creation of these scripts:
- https://madaidans-insecurities.github.io/guides/linux-hardening.html
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
- https://wiki.archlinux.org/
- https://www.cisecurity.org/benchmark/red_hat_linux
- https://www.cisecurity.org/benchmark/distribution_independent_linux
- https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
- https://github.com/a13xp0p0v/kconfig-hardened-check/
