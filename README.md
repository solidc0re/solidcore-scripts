# solidcore-scripts
Hardening scripts for immutable Fedora

Work in progress...

solidcore-install.sh is currently operational and functioning

To do:
- test dnscrypt-proxy and update settings
- test firstboot script
- tighten user interaction, currently y/n questions can fail on incorrect input
- review sysctl hardening (not needed if we can get server-side signing of hardened kernel to work)
- implement pam.d overwrites with stronger defaults (to meet CIS requirements)
- review additional CIS recommendations and update scripts further
- create scripts to audit all relevant settings on new versions of Fedora


## Resources
Resources used in the creation of these scripts:
- https://madaidans-insecurities.github.io/guides/linux-hardening.html
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
- https://wiki.archlinux.org/
- https://www.cisecurity.org/benchmark/red_hat_linux
- https://www.cisecurity.org/benchmark/distribution_independent_linux
- https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
- https://github.com/a13xp0p0v/kconfig-hardened-check/
