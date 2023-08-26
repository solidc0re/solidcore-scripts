# solidcore-scripts
Hardening scripts for immutable Fedora

Work in progress...

To do:
- review sysctl hardening
- implement pam.d overwrites with stronger defaults
- review CIS recommendations and update scripts further
- test scripts
- tidy and beautify scripts
- create scripts to audit all relevant settings on new versions of Fedora
- for uninstall script: re-add fedora flatpak repo and reinstall apps that were originally from that repo

Resources used in the creation of these scripts:
- https://madaidans-insecurities.github.io/guides/linux-hardening.html
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/index
- https://wiki.archlinux.org/
- https://www.cisecurity.org/benchmark/red_hat_linux
- https://www.cisecurity.org/benchmark/distribution_independent_linux
- https://static.open-scap.org/ssg-guides/ssg-fedora-guide-index.html
- https://github.com/a13xp0p0v/kconfig-hardened-check/
