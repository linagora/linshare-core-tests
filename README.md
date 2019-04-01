
# linshare-core-tests

# Install 

$ apt update
$ apt install bash-completion virtualenvwrapper python-pip

# Virtual env management

## list virtual env

$ workon

if you encountered this problem :  `zsh: command not found: workon`
do this :

$ source /etc/bash_completion.d/virtualenvwrapper


## create a virtual env

You must be in this directory, then launch:

$ mkvirtualenv -p python3 -a $(pwd) $(basename $(pwd))

If u can't create your virtual env because of this :
`The path /home/user/workspace/linshare-core-tests/python3 (from --python=/home/user/workspace/linshare-core-tests/python3) does not exist`

#### do this :
Check if python3 is already install :

$ python3

Find his repertory :

$  which python3

Replace python3 inside this line by the repertory of python3 :

$ mkvirtualenv -p /usr/bin/python3 -a $(pwd) $(basename $(pwd))

## enter in a virtual env

$ workon linshare-core-tests


# Configuration

$ cp linshare.admin.ini.sample linshare.admin.ini 
$ vim linshare.admin.ini

# Launch tests

$ ./tests_linshare.py

# Eclipse for Python

- Donwload "PyDev" form Eclipse MarketPlace
- Go to -> Windows, Preferences, Python Interpreter
- Select in the menu on the right  "Choose from List" and select python3
- Apply and close, now run
