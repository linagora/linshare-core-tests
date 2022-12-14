[![pylint](https://ci.linagora.com/linagora/lgs/linshare/products/linshare-core-tests/-/jobs/artifacts/master/raw/badges/pylint_badge.svg?job=pylint_badge)](https://ci.linagora.com/linagora/lgs/linshare/products/linshare-core-tests/-/jobs/artifacts/master/browse?job=pylint_badge)


# linshare-core-tests

## Browse Gitlab artefacts

* https://ci.linagora.com/linagora/lgs/linshare/products/linshare-core-tests/-/jobs/artifacts/master/browse?job=pylint_badge

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
Check if python3 is already installed :

$ python3

Find his repertory :

$  which python3

Replace python3 inside this line by the repertory of python3 :

$ mkvirtualenv -p /usr/bin/python3 -a $(pwd) $(basename $(pwd))

## enter in a virtual env

$ workon linshare-core-tests
Depreacted. old tests.

## Install required dependencies

$ pip install requests requests_toolbelt clint docker-compose

# Configuration

$ cp linshare.admin.ini.sample linshare.admin.ini
$ cp linshare.user.ini.sample linshare.user.ini
$ vim linshare.admin.ini linshare.user.ini

# Launch tests

$ docker-compose pull; docker-compose down; docker-compose up -d



$ ./tests_linshare.py

# Eclipse for Python

- Donwload "PyDev" form Eclipse MarketPlace
- Go to -> Windows, Preferences, Python Interpreter
- Select in the menu on the right  "Choose from List" and select python3
- Apply and close, now run
