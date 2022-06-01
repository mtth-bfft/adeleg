# ADeleg

![Build](https://github.com/mtth-bfft/adeleg/actions/workflows/test.yml/badge.svg) ![Release](https://img.shields.io/github/v/release/mtth-bfft/adeleg) ![Issues](https://img.shields.io/github/issues-raw/mtth-bfft/adeleg)

Is an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest, along with their potential issues:

- Objects owned by users
- Objects with ACEs for users
- Non canonical ACL
- Disabled ACL inheritance
- Default ACL modified in schema
- Deleted delegation trustees

It also allows you to document your delegation model in JSON files, to obtain a more readable view: 

## Usage

Download the [latest release here](https://github.com/mtth-bfft/adeleg/releases/latest) and double click on it for a graphical interface:

![Screenshot of GUI](docs/images/screenshot_gui.png)

You can also use the tool from a terminal by passing any option to it (if you don't want to pass any particular option, just use `--text`):

![Screenshot of CLI](docs/images/screenshot_cli.png)

If you want to export results, you can choose a CSV output using `--csv my.csv`
This is also suitable if you are interested in differences introduced since a previous dump (e.g. in PowerShell, `diff (cat export_new.csv) (cat export_old.csv)` )

Results should be concise in forests without previous work in delegation management. If results are too verbose to be used, open an issue describing the type of results obscuring interesting ones, ideally with CSV exports or screenshots.

You can start using this inventory right away, in two ways:

1. look for highly privileged resources which have no reason to have any delegation set up on them, since they are only supposed to be managed by forest-wide administrators

![View by resource](docs/images/view_by_resource.png)

2. you can also start the other way around, and look for trustees which have no reason to have any right delegated to them (e.g. day-to-day end user accounts)

![View by trustee](docs/images/view_by_trustee.png)


## FAQ

_How do I know if one result is important? Should I consider everything a problem?_ You should start reviewing delegations on your critical assets (domain controllers, domain admins, their admin workstations, servers with sensitive business data, etc.): are these delegations needed for a user or service to do their work? could they not work with fewer access rights, or on fewer objects?

_My forest has years of delegations built up, how am I supposed to handle that many warnings?_ You may want to run the analysis periodically and only focus on differences, so that you can start from a baseline and clean up delegations little by little over time.

_Can I import results from this tool into product <X>?_ Yes, if your tool knows how to parse CSV: `.\adeleg.exe --csv dump.csv`

## Copyright

All icons packaged with this project are the property of Microsoft Corporation.
For source code licensing, see LICENSE.md.