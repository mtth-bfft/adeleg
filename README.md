# ADeleg

![Release](https://img.shields.io/github/v/release/mtth-bfft/adeleg) ![Issues](https://img.shields.io/github/issues-raw/mtth-bfft/adeleg)

Is an Active Directory delegation management tool. It allows you to make a detailed inventory of delegations set up so far in a forest, along with their potential issues:

- Objects owned by users
- Objects with ACEs for users
- Non canonical ACL
- Disabled ACL inheritance
- Default ACL modified in schema
- Deleted delegation trustees

It also allows you to document your delegation model in JSON files, to obtain a more readable view: 

## Usage

The tool is currently being re-written in C#. If you just want a basic version with functioning but limited capabilities, just download the [latest release here](https://github.com/mtth-bfft/adeleg/releases/latest) and double click on it for a graphical interface.

If you want to beta-test the new version, you will have to compile it manually. Be aware that you *will* encounter false-positives and/or false-negatives, but you won't be on your own: open an issue with an example and what the expected output should be.

## How does it work?

This tool enumerates security descriptors of all objects, then filters out "expected" ACEs:

- Inherited ACEs, since we are only interested in the original ACE upper in the tree;
- ACEs in the `defaultSecurityDescriptor` of the object class in the schema;
- Some special cases which need to be handled manually.

Special cases currently include:
- object owners under a container with a `CREATE_CHILD` delegation
- ACEs for `CREATOR_OWNER` which are replaced and split in two in some cases during inheritance
- AdminSDHolder ACEs, for principals with `adminCount` set to 1
- KDS Root Keys, RODCs, ADCS, ADFS, Exchange, etc. are work in progress

## Copyright

All icons packaged with this project are the property of Microsoft Corporation.
For source code licensing, see LICENSE.md.
