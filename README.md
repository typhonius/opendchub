opendchub [![Build Status](https://travis-ci.org/odchbot/opendchub.svg?branch=master)](https://travis-ci.org/odchbot/opendchub)
=========

Instructions
------------

1. Download the install script from [here](https://raw.github.com/odchbot/opendchub/master/install.sh)
1. Make the script executable
1. Run the script

The above may be accomplished with the following one liner
````wget -q https://raw.github.com/odchbot/opendchub/master/install.sh && chmod +x install.sh && ./install.sh````

The script above does the following:

1. Creates a user called 'hub'
2. Adds hub to sudoers
3. Downloads all ODCH prerequisites
4. Configures stunnel to run on port 7659 & 7660
5. Install ODCH to run on port 8145
6. Installs [ODCHBot](https://github.com/odchbot/odchbot)
7. Preconfigures the admin user/password (The password is hashed so pay attention when the script tells you what the details are)

This script works best on a bare ubuntu install but may work on existing systems. It installs all the things necessary to run OpenDCHub and starts the service. Expect no support if this script doesn't work or trashes your system. It has worked prior on ubuntu precise, quantal and raring.

gl;hf
