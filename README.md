DumpVTable
==========

This program generates a Python script to give public interface names in an ActiveX file to the IDA Pro database file (IDB).

Usage
-----------------
    >DumpVTable.exe
    usage:
        >this.exe target_file out_file [-r] [-y]

        target_file: A path of a target COM file.
        out_file: A file name of an output Python script.
        -r: Register a target file as COM during analysis.
            It may require Administrators privilege.
        -y: Do not show a warning message.

As an example, assuming that you are going to analyze Flash10zr.ocx with IDA Pro.

First, you can use this tool to create a Python script (out.py).

    >DumpVTable.exe C:\Windows\SysWOW64\Macromed\Flash\Flash10zr.ocx out.py

Next, you can open the target file with IDA Pro.

![Before](/img/before.png)

Then, you apply the script to the IDB from [File] > [Script file] menu on IDA Pro.

![After](/img/after.png)

That's it. Have fun!


Note
-----------------
- When you see the error message 'ERROR: CoCreateInstance returned 80040154', you will need to register the target file with a command line option '-r'.
- When you see the error message 'ERROR: File mismatch [<path>]', you will need to specify <path> as a target file.


Supported Platforms
-----------------
- Windows 10 x64
- IDA Pro 7.3 and later
- Cannot handle 64bit target files.

License
-----------------
This software is released under the MIT License, see LICENSE.
