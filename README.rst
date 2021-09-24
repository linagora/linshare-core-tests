# Description

TODO

# Installation

$ pip install -e .

# display all collected tests:

$ pytest linshare_core_tests/  --collect-only

# display captured logs

Just add some "print" statement and then use -s flag to see the result.

$ pytest -vv --color=yes linshare_core_tests/  -k test_config -s 

# Run tests manually

* To run manually your tests, a package, a module or just a method

$ pytest -vv --color=yes --log-level=DEBUG linshare_core_tests
or 
$ pytest -vv --color=yes --log-level=DEBUG linshare_core_tests/test_admin_v5_functionalities.py
or
$ pytest -vv --color=yes --log-level=DEBUG linshare_core_tests -k test_find_all_functionalites_and_subs

When the test failed, and only when, you can sell the debug traces you added using
--log-level=DEBUG. Otherwise only info messages will be displayed.


# Tests run by the ci

$ tox
