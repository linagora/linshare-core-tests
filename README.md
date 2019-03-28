# linshare-core-tests

# Install 

$ apt update
$ apt install bash-completion virtualenvwrapper python-pip

# Virtual env management

## list virtual env

$ workon

## create a virtual env

You must be in this directory, then launch:

$ mkvirtualenv -p python3 -a $(pwd) $(basename $(pwd))

## enter in a virtual env

$ workon linshare-core-tests


# Configuration

$ cp linshare.admin.ini.sample linshare.admin.ini 
$ vim linshare.admin.ini

# Launch tests

$ ./tests_linshare.py

