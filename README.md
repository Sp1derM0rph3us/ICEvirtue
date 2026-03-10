# Introduction
ICEvirtue is the netrunner's most essential tool. It executes a standarized reconnaissance and enumeration pipeline and stores it inside **target profiles**, allowing netrunners to focus on what really matters: cracking those defenses.

# Installation
This software was made to work inside a Linux distribution. You can easily install it by utilizing go installer:

#### Debian
```Shell
sudo apt install golang -y
go install github.com/Sp1derM0rph3us/ICEvirtue@latest
```

# Usage
Be sure that you've added go's directory to your PATH. It is recommended to run the server as root.

#### Basic Usage
It will run the server with all it's functionalities turned on. The web GUI runs on the default port '8888':
```Shell
ICEvirtue
```

To run the server in a custom port, run it with the `--api-port` flag:
```Shell
ICEvirtue --api-port {desired-port}
```

To run the server without running amass or nuclei when scanning targets, add the flag:
```Shell
ICEvirtue --skip-amass # To skip amass during scanning
# OR
ICEvirtue --skip-nuclei # To skip nuclei usage during scanning
```

Your's trully is a bit dumb so to add users (including your own first user) you will need to go through some hoops (to be fixed soon)

1. Access go home's directory;
2. Then access `'/pkg/mod/github.com/!sp1der!m0rph3us!'`
3. There will only be one directory inside of it (and it will look weird), access it too
4. then you will be inside the original project directory, which then you can access `/cmd/admin` and compile the add-user code

```Shell
cd '/pkg/mod/github.com/!sp1der!m0rph3us!'
cd '{only-directory-inside}'
cd cmd/admin
go build -o /path/for/compiled/binary/add-user main.go
```

To add an user:

```Shell
./add-user create -username 'your-username' -password 'super-secret-password'
```

If your password have special symbols, I recommend wrapping it around single quotes. If successfull, you should be able to login already.

# Disclaimer
ICEvirtue is a work-in-progress and it is mainly created for my specific needs. Although I might add specific functionalities per request, you are much welcome to fork this project and use it as a baseline to start your own if you have specific needs or visions. This project is also created using AI, so take much care when exposing it for access over the Net.

That been said, it is being developed with ample focus on security, so you don't get ass whooped by another 'runner while you are asleep. I super appreciate bug reports and vulnerability disclosures, feel absolutely free to mess around with this project in your lab environment and report anything you might find. I will absolutely love to hear and fix such bugs.


#### THIS README IS ALSO A WORK-IN-PROGRESS. IT WILL LOOK PRETTIER WHEN YOU VISIT THIS PAGE AGAIN (hopefully)
