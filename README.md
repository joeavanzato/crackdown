<h1 align="center">
crackdown
</h1>
<p align="center">
<img src="assets/cd3.png">
</p>
<h2 align="center">
Linux Persistence Hunter
</h2>
 
### Linux Persistence Hunter

#### What is it?

crackdown is a command-line utility designed to aid Incident Responders in the detection of potential adversary persistence mechanisms on Linux-based operating systems.

It must be run as sudo to be effective.

#### What is inspected?

* **Running Processes** [T1059]
  * Suspicious Terms, Abnormal exe locations
* **Active TCP Connections** [T1071]
  * Suspicious Ports, Unusual processes with connections
* **Cron Jobs** [T1053.003]
  * Suspicious Keywords, General Command Review
* **Local Users** [T1136.001]
* **SSH Authorized Keys** [T1098.004]
* **Modified Kernel Modules** [T1547.006]
* **Modified .bashrc Files** [T1546.004]

#### MITRE Techniques Inspected
* T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions
* T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification
* T1098.004 - Account Manipulation: SSH Authorized Keys
* T1136.001 - Create Account: Local Account
* T1053.003 - Scheduled Task/Job: Cron
* T1071 - Application Layer Protocol
* T1059 - Command and Scripting Interpreter

TODO:
* SUID Binary Modification
* Startup Service Examination
* MOTD Modification
* User Startup File Modification
* Driver Modification
* apt Backdoor
* git Backdoor
* git Hooks
* Installed Kernel MOodules
* doas conf file 
* at allow config file
* sudoers tmp file
* visudo utility execution
* .bashrc/zshrc modification
* Non-standard binary installation