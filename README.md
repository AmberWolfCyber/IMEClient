# IMEClient

Command line client for Company Portal - allows you to list, install and uninstall apps via Intune, mimicking the functionality from the Company Portal app.

See blog: https://blog.amberwolf.com/blog/2026/october/company-portal-self-service-to-system/

## Demo

![demo](demos/demo.png)

## Privilege Escalation

This can be used for privilege escalation via known race-condition and TOCTOU vulnerabilities in installer packagers.

The following example shows a known vulnerable installer packager (NSIS):

[Watch demo](https://vimeo.com/1233705055)
