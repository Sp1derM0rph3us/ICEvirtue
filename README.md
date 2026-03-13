# Introduction
ICEvirtue is the netrunner's most essential tool. It executes a standarized reconnaissance and enumeration pipeline and stores it inside **target profiles**, allowing netrunners to focus on what really matters: cracking those defenses.

# Recon & Enumeration Workflow
The application follows a solid continuos reconnaissance workflow that is battletested, separated in stages:

Stage 01 - Basic Recon:
The application runs [Subfinder](https://github.com/projectdiscovery/subfinder) and [Amass](https://github.com/owasp-amass/amass) for subdomain and asset discovery. If provided a wordlist it also runs [DNSX](https://github.com/projectdiscovery/dnsx) for active DNS enumeration.

Stage 02 - Web Validation:
Afterwards, the application validates all findings with [HTTPX](https://github.com/projectdiscovery/httpx). In the web dashboard, all findings (alive or not) will be saved, but HTTPX allows for the enhanced execution of the next stages, avoiding files and directory fuzzing as well as secrets hunting in dead (or inaccessible) assets.

Stage 03 - Directory and File Fuzzing:
Next, the application will execute a multi-threaded directory and file fuzzing (with a custom fuzzer). The user can provide multiple wordlists, the engine will automatically de-duplicate wordlists for maximum effective coverage. In this stage, only findings with status code 200, 3xx and 403 and 405 are considered valid.

Stage 04 - Vulnerability Scanning:
Approaching the final step of execution, the application (if not provided `--skip-nuclei` flag) will run [Nuclei](https://github.com/projectdiscovery/nuclei) against all (valid) assets in order to identify vulnerabilities, missconfigurations and what-not.

Stage 05 - Secret Hunting:
In the final step of the execution, the application will run a series of tools to both identify and execute a search for hard-coded secrets and credentials inside identifiable historical and current JS files. The software **currently** utilizes a series of widely known tools ([Gau](https://github.com/lc/gau), [Subjs](https://github.com/lc/subjs), [Katana](https://github.com/projectdiscovery/katana), [Mantra](https://github.com/brosck/mantra) and [SecretFinder](https://github.com/m4ll0k/SecretFinder)) to accomplish this objective.

# Installation
## From Source
```Shell
sudo su
# type in sudo password...

git clone https://github.com/Sp1derM0rph3us/ICEvirtue.git
cd ICEvirtue
go build -o /usr/bin/ICEvirtue main.go # Compiles the actual application so it can run
go build -o /usr/bin/ICEvirtue-admin cmd/admin/main.go # Compiles the admin tool so you can add users (there is no default user, you need to create one)
chmod 775 /usr/bin/ICEvirtue*
```
# Usage
First of all, **you need to have all previously mentioned tools installed in your machine so the application can properly run**. You can access them by clicking their names in "Recon and Enumeration Workflow" section. Also, add the tools to your PATH (or to your .service file "Environment" variable).

#### Setting Up Users
Inside the folder you want as the application's working directory (in a server environment with ICEvirtue configured to run as a service this might be different than a casual environment where you locally run it from your terminal), run:
```Shell
ICEvirtue-admin create --username 'username' --password 'super-secret-password'
```
This will generate all the necessary `.db` files.

#### Running The Application
If you are going to run the application as a service, the `web` folder must be inside the application's working directory (for instance, `/opt/icevirtue`) before running the application, so you might want to run:
```Shell
cp -r ./ICEvirtue/web /opt/icevirtue
```
##### Basic Usage
The most basic way to run the application is:
```Shell
ICEvirtue --directory-list /path/to/wl1,/path/to/wl2,/path/to/wl3, --dnsx-list /path/to/wl1,/path/to/wl2 --verbose
```

This will execute ICEvirtue in "Full-Mode", which will execute Amass, Nuclei and dnsx together with the other steps of the workflow, while also providing more information in the terminal logs. By default, the application runs on port 8888/tcp. You can change the running port by utilizing the flag `--api-port`
```Shell
ICEvirtue --api-port 2077 # [...]
```

If you don't want to run Amass or Nuclei for some reason (e.g. testing, target infrastructure limitation, VPS limitations, etc) you can turn one, the other or both off by running the application with `--skip-nuclei` and/or `--skip-amass` flags.
```Shell
ICEvirtue --directory-list /path/to/wl1 --dnsx-list /path/to/wl1 --skip-nuclei --skip-amass
```

If you **don't** want to run `dnsx` you can simply **not add `--dnsx-list`**, which will prompt the app to skip dnsx enumeration.
#### The Web Interface
The web interface is pretty straight forward. You must add a target domain (e. g. `hackerone.com`) and how often you want the application to scan them (daily, monthly or yearly) and by what time of the day. If you are hosting this in a VPS, take care to take note what UTC your server utilizes since you can't currently define a different one for the application (it follows the system time). This might cause your scan to run in a different time instead of the one you inteded.

Once a scan starts, it will **first** update the "Discoveries" tab once the initial recon phase is finished. Then, it will complement each finding when the other stages are done. You can access a finding information by clicking on it. You can access the finding itself (e. g. `www.example.com`) by clicking on the icon in the far-right of the specific finding row.

If you want to access all identified secrets in a target profile, you can click the `Secrets` tab in the root `Discoveries` tab. If you want to change target profile, select one in `Select Profile` drop-down menu. The dashboard is dinamically updated, so you do not have to F5 to see changes in target status and in findings. Just wait for the workflow to finish and there it is.

# Disclaimer
ICEvirtue is a work-in-progress and it is mainly created for my specific needs. Although I might add specific functionalities per request, you are much welcome to fork this project and use it as a baseline to start your own if you have specific needs or visions. This project is also created with the help of AI, so take much care when exposing it for access over the Net.

That been said, it is being developed with ample focus on security, so you don't get ass whooped by another 'runner while you are asleep. I super appreciate bug reports and vulnerability disclosures, feel absolutely free to mess around with this project in your lab environment and report anything you might find. I will absolutely love to hear and fix such bugs.


#### THIS README IS ALSO A WORK-IN-PROGRESS. IT WILL LOOK PRETTIER WHEN YOU VISIT THIS PAGE AGAIN (hopefully)
