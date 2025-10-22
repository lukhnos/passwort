# Passwort: A Command-Line Password Manager

Passwort (German for password) is a command-line password manager written in
Python.


## Motivation

This is a holiday project I created to learn more about practical
cryptography, product development, and Python.

Initially, I wanted to create a command-line password manager to replace the
commercial password manager that I was using. I also surveyed a number of
open-source password managers. Many of them depend heavily on GUI toolkit
(X11, wxWidgets, etc.) because they need to be cross-platform. There are also
a number of simple command-line tools that are written in shell script and
built upon gpg.

In the end, I found that it might be easier to start from scratch. The file
format should be simple to allow interoperability, so I chose JSON. I also
didn't spend much effort thinking out versioning or supporting more than one
cipher or HMAC scheme -- although with a simple JSON format it should be easy
to migrate data in the future.


## Warnings and Disclaimers

This program is not vetted by any security expert, and if this may be a
problem for you, do not use the program.

Also, for simplicity, this program does not do any key derivation. Instead,
it expects you to supply a 256-bit key either from stdin or a file. You may
want to encrypt the file using gpg and chain the command accordingly. More on
that below.


## Install

To install:

	pip3 install -e .

You may need to add `sudo` in front of the command line. Passwort depends
on [PyCrypto](https://www.dlitz.net/software/pycrypto/) and
[pwgen](https://github.com/vinces1979/pwgen), and the setup script should be
able to install them for you if you haven't.


## Creating and Using the Key File

To create the encryption key for your data:

	passwort --generate-key-to-stdout > foo.key

You may want to protect the key file. A typical approach is to use gpg to
encrypt the key, keep the encrypted file, and use gpg to decrypt the key when
you need it:

	gpg -r [your email] -e foo.key
	rm foo.key
	gpg -d foo.key.gpg | passwort --key-from-stdin [commands...]

If you are comfortable with using the key file directly (e.g. if you store
the key file in an encrypted drive), you can also use this form:

	passwort --key foo.key [commands...]

The examples below all use the key file directly.


## Creating and Updating Password Entries

To create or update an entry, use:

	passwort --key foo.key --file foo.json --node example.com --set-username johndoe --set-password

This creates a new node under the name `example.com`. It will also prompt you
to enter and confirm the password. The password file is saved to `foo.json`.
If the file does not exist yet, Passwort will create it for you, otherwise
it will first read the file and insert (or replace) the fields of the node.

If you want Passwort to generate the Passwort for you, use:

	passwort --key foo.key --file foo.json --node example.com --set-username johndoe --generate-and-set-password 32

This generates a 32-character password. The generated password will always
contain at least one capital letter and one symbol (the default symbol set
is `,.;!-`) and will not contain any space.

## Reading Entries

To read the username:

	passwort --key foo.key --file foo.json --node example.com --get-username

To read the password:

	passwort --key foo.key --file foo.json --node example.com --get-password

You may want to pipe the password to your pasteboard tool. For example, on
OS X:

	passwort --key foo.key --file foo.json --node example.com --get-password | pbcopy

If you are piping it, Passwort will *not* add a newline to the retrieved
password.


## Editing and Showing Notes

You may also want to add free-form notes in your password file:

	passwort --key foo.key --file foo.json --node example.com --edit-note
	passwort --key foo.key --file foo.json --node example.com --show-note

Your default editor (vim, nano, etc. depending on your settings) will be
invoked to edit the note.


## Dumping the Password File

Sometimes you way want to dump the entire file:

	passwort --key foo.key --file foo.json --dump > foo.tsv

The output is a tab-separated file with three columns in each line: node
name, username, and password. If a field does not have a value, it will be
dumped as `None`.

Note that `--dump` does not dump notes.


## Notes and Thoughts

*	Passwort uses AES in CBC mode with 256-bit key as the cipher,
	and SHA-256 for the HMAC. With the data format it should be relatively
	easy to use other ciphers and HMAC hash functions.
*	With the JSON data it is easy to write tools that don't need to decrypt
	the textual data. For example, password rotation reminder can simply use-
	the `timestamp` field to remind you that a password should be updated.
*	It is also possible to do things like password strength auditing with the
	`Keychain` class. Simply traverse the nodes, and measure each password's
	strength.
*	Initially I wanted to keep the history of passwords used, but in the end
	decided to keep things simple.
*	A practical password manager needs to be much easier and faster to use,
	and for that it requires a lot of user interface work. It will also need
	to have some basic integration with the GUI desktop -- such as the
	ability to send the password to the pasteboard, and clean the pasteboard
	after the machine being idle for a certain period of time, and so on.
	I think that's the value provided by the established (commercial or free
	and open source) password manager products. This being said, you may
	still want to use your own password manager to store the most important
	ones.
*	It may be worth providing an option to use password-derived key instead
	of using a key file. The question would be if we should store the key
	derivation parameters in the password file. For example,
	[encfs](http://www.arg0.net/encfs) saves that piece of information in
	a separate file. The purpose is to specify the number of rounds when
	running the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) function to
	achieve the desired delay -- the faster the machine, the more rounds it
	uses.

