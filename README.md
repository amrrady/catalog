# Catalog App

Catalog is a web application to view, add, edit, delete categories and items related to it.

## Supported Features

1. Login, Logout
2. View categories, and their items
3. Add Category, and items associated with it. (Only if you are logged in)
4. Edit your own Categories, and items associated with them. (Only if you are logged in)
5. Delete your own Categories, and items associated with them. (Only if you are logged in)

## Technologies

* Python version: 3.7
* sqlalchemy, sqlite database
* Flask
* Google OAuth 2.0

# Prepare your environment

To start on this project, you'll need make sure that all these tools are installed in your environment
* Python version: 3.7
* sqlalchemy, sqlite database
* Flask

or you can use Vagrant by following the next steps

### Install VirtualBox

VirtualBox is the software that actually runs the virtual machine. You can download it from virtualbox.org
Ubuntu users: If you are running Ubuntu 14.04, install VirtualBox using the Ubuntu Software Center instead.
### Install Vagrant
Vagrant is the software that configures the VM and lets you share files between your host computer and the VM's filesystem. Download it from vagrantup.com
### Download the VM configuration
Use Github to fork and clone this [repository](https://github.com/udacity/fullstack-nanodegree-vm)

Change to this directory in your terminal with `cd`. Inside, you will find another directory called _vagrant_ . Change directory to the vagrant directory.

### Start the virtual machine

* From your terminal, inside the _vagrant_ subdirectory, run the command `vagrant up`. This will cause Vagrant to download the Linux operating system and install it. This may take quite a while (many minutes) depending on how fast your Internet connection is.

* When vagrant up is finished running, you will get your shell prompt back. At this point, you can run `vagrant ssh` to log in to your newly installed Linux VM!


# Usage
* clone this repo using command `git clone https://github.com/amrrady/catalog.git`
* cd to catalog folder
* make sure that the folder is writable by running `chmod -Rf 777 .`
* run the server using this command `./project.py`

## Visit http://localhost:5000/category to try the porject
