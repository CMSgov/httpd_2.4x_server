## Apache Server STIG Automated Compliance Validation Profile
<b>Apache Server 2.4</b>
**CMS’ ISPG (Information Security and Privacy Group) decided to discontinue funding the customization of MITRE’s Security Automation Framework (SAF) for CMS after September 2023. This repo is now in archive mode, but still accessible. For more information about SAF with current links, see https://security.cms.gov/learn/security-automation-framework-saf**


<b>Apache Server 2.4</b> STIG Automated Compliance Validation Profile works with Chef InSpec to perform automated compliance checks of <b>Apache Server</b>.

This automated Security Technical Implementation Guide (STIG) validator was developed to reduce the time it takes to perform a security check based upon STIG Guidance from DISA. These check results should provide information needed to receive a secure authority to operate (ATO) certification for the applicable technology.
<b>Apache Server</b> uses [Chef InSpec](https://github.com/chef/inspec), which provides an open source compliance, security and policy testing framework that dynamically extracts system configuration information.

## Apache Server STIG Overview

The <b>Apache Server</b> STIG (https://public.cyber.mil/stigs/) by the United States Defense Information Systems Agency (DISA) offers a comprehensive compliance guide for the configuration and operation of various technologies.
DISA has created and maintains a set of security guidelines for applications, computer systems or networks connected to the DoD. These guidelines are the primary security standards used by many DoD agencies. In addition to defining security guidelines, the STIG also stipulates how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

[STIG](https://en.wikipedia.org/wiki/Security_Technical_Implementation_Guide)s are the configuration standards for United States Department of Defense (DoD) Information Assurance (IA) and IA-enabled devices/systems published by the United States Defense Information Systems Agency (DISA). Since 1998, DISA has played a critical role enhancing the security posture of DoD's security systems by providing the STIGs. The STIGs contain technical guidance to "lock down" information systems/software that might otherwise be vulnerable to a malicious computer attack.

The requirements associated with the <b>Apache Server</b> STIG are derived from the [National Institute of Standards and Technology](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology) (NIST) [Special Publication (SP) 800-53, Revision 4](https://en.wikipedia.org/wiki/NIST_Special_Publication_800-53) and related documents.

While the Apache Server STIG automation profile check was developed to provide technical guidance to validate information with security systems such as applications, the guidance applies to all organizations that need to meet internal security as well as compliance standards.

### This STIG Automated Compliance Validation Profile was developed based upon:
- Apache Server Security Technical Implementation Guide
### Update History 
| Guidance Name  | Guidance Version | Guidance Location                            | Profile Version | Profile Release Date | STIG EOL    | Profile EOL |
|---------------------------------------|------------------|--------------------------------------------|-----------------|----------------------|-------------|-------------|
| Apache Server 2.4 STIG  | Ver 2, Rel 2    | https://public.cyber.mil/stigs/downloads/  |         1.0.0          |        28 Jan 2021           | NA | NA |
|


## Getting Started

### Setup Environment on STIG Validation Execution Host

#### Apache Server  
- Apache Server
- Account providing appropriate permissions to perform audit scan

#### Ensure your InSpec version is at least 4.23.10 <b>[update or remove section based upon technology]</b>
```sh
inspec --version
```

#### Required software on Apache Server machine
- git
- [InSpec](https://www.chef.io/products/chef-inspec/)

### Setup Environment on Apache Server machine 
#### Install InSpec
Goto https://www.inspec.io/downloads/ and consult the documentation for your Operating System to download and install InSpec.

#### Ensure InSpec version is at least 4.23.10 
```sh
inspec --version
```

### How to execute this instance  
(See: https://www.inspec.io/docs/reference/cli/)

#### Execute a single Control in the Profile 
**Note**: Replace the profile's directory name - e.g. - `<Profile>` with `.` if currently in the profile's root directory.
```sh
inspec exec <Profile>/controls/V-72841.rb --show-progress
```
or use the --controls flag to execute checking with a subset of controls
```sh
inspec exec <Profile> --controls=V-72841.rb V-72845.rb --show-progress
```

#### Execute a Single Control and save results as JSON 
```sh
inspec exec <Profile> --controls=V-72841.rb --show-progress --reporter json:results.json
```

#### Execute All Controls in the Profile 
```sh
inspec exec <Profile> --show-progress
```

#### Execute all the Controls in the Profile and save results as JSON 
```sh
inspec exec <Profile> --show-progress  --reporter json:results.json
```

## Check Overview

**Manual Checks**

These checks are not included in the automation process.

| Check Number | Description                                                                                                                                                                                                                                                                          |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| V-92621      | An Apache web server, behind a load balancer or proxy server, must produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.                                                               |
| V-92627      | The Apache web server must use a logging mechanism that is configured to alert the Information System Security Officer (ISSO) and System Administrator (SA) in the event of a processing failure.                                                                                          |
| V-92635      | The log data and records from the Apache web server must be backed up onto a different system or media.                                                                                                                                                                                    |
| V-92637      | Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Apache web server.                                                                                                                                                                      |
| V-92641      | The Apache web server must only contain services and functions necessary for operation.                                                                                                                                                                                                    |
| V-92645      | The Apache web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.                                                                                                                                         |
| V-92655      | The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.                                                                                                                                                                                              |
| V-92671      | Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.                                                                                                                                |
| V-92673      | Apache web server application directories, libraries, and configuration files must only be accessible to privileged users.                                                                                                                                                                 |
| V-92675      | The Apache web server must separate the hosted applications from hosted Apache web server management functionality.                                                                                                                                                                        |
| V-92695      | The Apache web server must be built to fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.                                                                                                                                                          |
| V-92709      | The Apache web server must restrict inbound connections from nonsecure zones.                                                                                                                                                                                                              |
| V-92711      | The Apache web server must be configured to immediately disconnect or disable remote access to the hosted applications.                                                                                                                                                                    |
| V-92713      | Non-privileged accounts on the hosting system must only access Apache web server security-relevant information and functions through a distinct administrative account.                                                                                                                    |
| V-92715      | The Apache web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the Apache web server.                                                                                               |
| V-92717      | The Apache web server must not impede the ability to write specified log record content to an audit log server.                                                                                                                                                                            |
| V-92719      | The Apache web server must be configured to integrate with an organizations security infrastructure.                                                                                                                                                                                       |
| V-92727      | The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.                                                                                                                                                            |
| V-92751      | The account used to run the Apache web server must not have a valid login shell and password defined.                                                                                                                                                                                      |
| V-92753      | The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.                                                                 |

**Normal Checks**

These checks will follow the normal automation process and will report accurate STIG compliance PASS/FAIL.

| Check Number | Description                                                                                                                                                                                                                                                                          |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| V-92597      | Apache web server management includes the ability to control the number of users and user sessions that utilize an Apache web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of denial-of-service (DOS) attacks. |
| V-92599      | Session management is the practice of protecting the bulk of the user authorization and identity information. This data can be stored on the client system or on the server.                                                                                                               |
| V-92601      | The Apache web server must use cryptography to protect the integrity of remote sessions.                                                                                                                                                                                                   |
| V-92607      | The Apache web server must have system logging enabled.                                                                                                                                                                                                                                    |
| V-92609      | The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.                                                                                                                                           |
| V-92629      | The Apache web server log files must only be accessible by privileged users.                                                                                                                                                                                                               |
| V-92631      | The log information from the Apache web server must be protected from unauthorized modification or deletion.                                                                                                                                                                               |
| V-92639      | The Apache web server must not perform user management for hosted applications.                                                                                                                                                                                                            |
| V-92643      | The Apache web server must not be a proxy server.                                                                                                                                                                                                                                          |
| V-92653      | The Apache web server must have resource mappings set to disable the serving of certain file types.                                                                                                                                                                                        |
| V-92659      | The Apache web server must have Web Distributed Authoring (WebDAV) disabled.                                                                                                                                                                                                               |
| V-92661      | The Apache web server must be configured to use a specified IP address and port.                                                                                                                                                                                                           |
| V-92677      | The Apache web server must invalidate session identifiers upon hosted application user logout or other session termination.                                                                                                                                                                |
| V-92679      | Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.                                                                             |
| V-92687      | The Apache web server must generate a session ID long enough that it cannot be guessed through brute force.                                                                                                                                                                                |
| V-92689      | The Apache web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.                                                                                                                                                         |
| V-92697      | The Apache web server must be tuned to handle the operational requirements of the hosted application.                                                                                                                                                                                      |
| V-92699      | Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.                                                                                                                          |
| V-92701      | Debugging and trace information used to diagnose the Apache web server must be disabled.                                                                                                                                                                                                   |
| V-92705      | The Apache web server must set an inactive timeout for sessions.                                                                                                                                                                                                                           |
| V-92723      | The Apache web server must generate log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT) which are stamped at a minimum granularity of one second.                                                                                              |
| V-92731      | The Apache web server must be protected from being stopped by a non-privileged user.                                                                                                                                                                                                       |
| V-92741      | Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.                                                                                                     |
| V-92745      | The Apache web server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.                                                                                                                                                              |
| V-92749      | The Apache web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).                                                                                                           |
| V-92755      | The Apache web server software must be a vendor-supported version.                                                                                                                                                                                                                         |
| V-92757      | The Apache web server htpasswd files (if present) must reflect proper ownership and permissions.                                                                                                                                                                                           |
| V-92759      | HTTP request methods must be limited.                                                                                                                                                                                                                                                      |
                                                                                                                                 
## Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

## Legal Notices

Copyright © 2020 Defense Information Systems Agency (DISA)
