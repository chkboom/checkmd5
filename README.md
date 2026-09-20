checkMD5 - Improved MD5 aggregate file checker
==============================================
This program is designed to present a user-friendly console interface to check a collection of files for corruption using the MD5 hash algorithm.

It is similar to md5sum except it has a progress indicator that can be cancelled by the user with Escape.
This is good for a boot-time media integrity check involving image files and other important data.

Integration with external programs
----------------------------------
The checkMD5 tool can provide progress indication in a format suitable for scripts and other programs such as dialog, zenity and yad.
```
checkmd5 --machine *.md5 | awk '!v[int($0)]++{print int($0); fflush()}' | dialog --gauge "Checking MD5 sums..." 6 50
checkmd5 --machine *.md5 | zenity --progress
checkmd5 --machine *.md5 | yad -progress
```
The `--machine` option makes checkMD5 produce lines that each contain the percentage of progress, in 0.1% increments.

How to Build
------------
Building checkmd5 requires some GNAT tools (for Ada) to be installed:
 * `gnat` - the GNAT Ada compiler.
 * `gprbuild` - To build the projects.
 * `alire` - the Alire package manager and tool chain executer.

### Main build procedure
Just go into the git working directory and run:
````
alr clean
alr build
````
Note that with `alr build` you can add options like `--release` for building a release version without debugging symbols and other runtime checks.

Versioning
----------

### Version 0.102
Rewritten in Ada 2022 (GNAT).

### Version 0.101
Various code quality and performance improvements.
Only write progress indication if stdout is ready to accept output.
 - Prevents stalling when output is suspended on the terminal.
Improved line break consistency across various options.
Replaced --gauge with --machine option.
 - Output percentage lines in 0.1% increments.
Added man page and updated documentation.
Added debian folder for deb package.

### Version 0.100
Various I/O performance improvements.
Ensure buffer size and target block sizes are integer multiples of the page size.
Read using current target block size instead of the whole buffer size.

### Version 0.99
Various usability fixes and improvements.
Various logging improvements.
Added --verbose and --force options.
Fixed: log file prepended with "="
Print progress information and messages to stdout.
 - Stops regular out being marked as error on Debian boot.
Add internationalization support.
Add "--" option to allow for files starting with hyphens.
Error handling improvements.