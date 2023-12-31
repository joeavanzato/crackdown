```
                        __       __                 
  ______________ ______/ /______/ /___ _      ______
 / ___/ ___/ __ '/ ___/ //_/ __  / __ \ | /| / / __ \
/ /__/ /  / /_/ / /__/ ,< / /_/ / /_/ / |/ |/ / / / /
\___/_/   \__,_/\___/_/|_|\__,_/\____/|__/|__/_/ /_/ 
```

<p align="center">
<img src="assets/cd3.png">
</p>
<h2 align="center">
crackdown - Linux Persistence Hunter
</h2>

#### What is it?

crackdown is a command-line utility designed to aid Incident Responders in the detection of potential adversary persistence mechanisms on Linux-based operating systems.

It must be run as sudo to be effective.

#### Usage

Just download the release and run as sudo:
```
sudo crackdown
sudo crackdown -quiet
```
Use the '-quiet' flag to suppress detections at the command-line - all detections are output to CSV/JSON output in the current working directory.

CSV output will store detection metadata in a JSON string within the Metadata column - other columns are normal strings.

<p align="center">
<img src="assets/usage1.png">
</p>
StdOut Output Example
<p align="center">
<img src="assets/usage2.png">
</p>
CSV Output Example
<p align="center">
<img src="assets/usage_csv.png">
</p>
JSON Output Example
<p align="center">
<img src="assets/usage_json.png">
</p>

#### What is inspected?

* **Running Processes** [T1059]
  * Suspicious Keywords, IP/Domain in Commandline, Running process with non-existent executable
* **Active TCP Connections** [T1071]
  * Suspicious Ports, Unusual processes with connections
* **Cron Jobs** [T1053.003]
  * Suspicious Keywords, General Command Review
* **Local Users** [T1136.001]
  * General Review, Privileged Users [TODO]
* **SSH Authorized Keys** [T1098.004]
  * Recent Modifications, General Review
* **Recently Modified Kernel Modules** [T1547.006]
* **Modified Shell Configuration Files** [T1546.004]
* **Created/Modified Service Files/Service Confs** [T1543.002]
  * /etc/systemd/system|user
  * /run/systemd/system|user
  * /lib/systemd/system|user
* **Environment Variable Scanning**
* **apt/git/doas/motd/Startup/at.allow|deny,etc Backdoors** [T1037.005]
* **Webshell Scan** [T1505.003]
  * /var/www
  * /etc/nginx
  * /etc/apache*
* **Broad Scanning for Suspicious Files**
  * /etc/update-motd.d 
  * /var/run/motd 
  * /etc/init.d 
  * /etc/rc.d 
  * /sbin/init.d 
  * /etc/rc.local 
  * /etc/apt/apt.conf.d 
  * /usr/share/unattended-upgrades
  * /home/*/.gitconfig
  * /etc/at.allow
  * /etc/at.deny
  * /etc/doas.conf
  * /home/*/. Scripts|Confs
  * /root/.*

#### MITRE Techniques Evaluated
* T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions
* T1546.004 - Event Triggered Execution: Unix Shell Configuration Modification
* T1098.004 - Account Manipulation: SSH Authorized Keys
* T1136.001 - Create Account: Local Account
* T1053.003 - Scheduled Task/Job: Cron
* T1071 - Application Layer Protocol
* T1059 - Command and Scripting Interpreter
* T1543.002 - Create or Modify System Process: Systemd Service
* T1037.005 - Boot or Logon Initialization Scripts: Startup Items
* T1505.003 - Server Software Component: Web Shell

TODO:
* git hooks/config finding
* at allow config file
* NOPSSWD Sudoers
* Recently Modified Binaries
* Privileged User Highlight


#### General References
* https://www.ibm.com/docs/en/zos/2.5.0?topic=daemon-format-authorized-keys-file
* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md
* https://www.linode.com/docs/guides/linux-red-team-persistence-techniques/
* https://cyberblueteam.medium.com/blue-team-tips-linux-os-finding-evil-running-process-3f12b17c3b8e
* https://pberba.github.io/assets/posts/common/20220201-linux-persistence.png
* https://github.com/xl7dev/WebShell
* https://medium.com/kernel-space/linux-fundamentals-a-to-z-of-a-sudoers-file-a5da99a30e7f
* 