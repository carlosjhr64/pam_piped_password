# Pam Piped Password

## Synopsis

	...
	auth optional   pam_piped_password.so /usr/local/bin/some_way_to_get_password
	auth sufficient pam_unix.so           try_first_pass
	...

The module provides a way to set PAM_AUTHTOK via a script.
The module expects a single argument, the name of the script to run.
It only passes PAM_USER as an enviroment variable.
It expects only a one line output which is used to set PAM_AUTHTOK.
It returs PAM_SUCCESS if all expectations are met, else returns PAM_IGNORE.
