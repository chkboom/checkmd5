checkMD5 - Improved MD5 aggregate file checker
==============================================
This program is designed to present a user-friendly console interface to check a collection of files for corruption using the MD5 hash algorithm.

It is similar to md5sum except it has a progress indicator that can be cancelled by the user with Escape.
This is good for a boot-time media integrity check involving image files and other important data.

The inspiration for this tool came from [isomd5sum](https://github.com/rhinstaller/isomd5sum) from Red Hat, which implants an MD5 checksum in an ISO.
This checkmd5 tool shares none of the code with checkisomd5, and operates on files created by md5sum (or "md5" on BSD systems).

Ideally, you should consider a package like isomd5sum as it will take the checksum of the whole image as one unit.
This tool is designed for verifying the files on a live USB drive, such as one created with [MX Live USB Maker](https://github.com/MX-Linux/mx-live-usb-maker).

Features
--------
* Accepts multiple checksum files on a single command line.
* Requirement of all targets to pass for successful verification.
* Optional log file support, machine and human friendly format.
  * Date and time the operation started.
  * Pass/fail result of each target, and expected vs calculated checksums.
  * Whether the operation was aborted, and at what point of completion.
  * The final overall result, as well as exit status.
* Percentage progress indication, with 0.1% resolution.
  * Option for machine-friendly progress output.
* Can be gracefully interrupted with Escape or a SIGINT (eg. Ctrl+C).

Integration with external programs
----------------------------------
The checkMD5 tool can provide progress indication in a format suitable for scripts and other programs such as dialog, zenity and yad.
```
checkmd5 --machine *.md5 | awk '!v[int($0)]++{print int($0); fflush()}' | dialog --gauge "Checking MD5 sums..." 6 50
checkmd5 --machine *.md5 | zenity --progress
checkmd5 --machine *.md5 | yad -progress
```
The `--machine` option will produce one line for each progress update, which typically means 1000 lines in total (100x 0.1% increments).  
The `awk` command in the first example discards the fractional component because `dialog` does not like the 0.1% resolution of the checkmd5 output.

Troubleshooting
---------------

### Long lines of text appear even without the --verbose option
This indicates that an attempt was made to write something to the log file has failed. When this happens, checkMD5 attempts to write the entry to the console.
If this fails, then there is nothing left to write to, so the entry is lost for all eternity.

This could happen if the storage device for the log file doesn't have enough space or checkMD5 has not been granted permission to write to the log file.
On some systems, a security framework such as AppArmor or SELinux may be interfering with the attempt to write to the log file.

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

Release Notes
-------------

### Version 0.103
* Fixed unhandled exception if terminal pipe breaks.
* Use correct terminal setup for progress interface.
* Cleanup source tree and fixed deb package build.
* Fixed "ERROR" when using the --help option.
* Add detection of unknown options.
* Fixed logging of abortions.

### Version 0.102
* Rewritten in Ada 2022 (GNAT).

### Version 0.101
* Various code quality and performance improvements.
* Only write progress indication if stdout is ready to accept output.
  * Prevents stalling when output is suspended on the terminal.
* Improved line break consistency across various options.
* Replaced --gauge with --machine option.
  * Output percentage lines in 0.1% increments.
* Added man page and updated documentation.
* Added debian folder for deb package.

### Version 0.100
* Various I/O performance improvements.
* Ensure buffer size and target block sizes are integer multiples of the page size.
* Read using current target block size instead of the whole buffer size.

### Version 0.99
* Various usability fixes and improvements.
* Various logging improvements.
* Added --verbose and --force options.
* Fixed: log file prepended with "="
* Print progress information and messages to stdout.
  * Stops regular out being marked as error on Debian boot.
* Add internationalization support.
* Add "--" option to allow for files starting with hyphens.
* Error handling improvements.
