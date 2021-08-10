# SUPERHOT Solution

The challenge name will appear as SUPER and the description as HOT on CTFd, but the actual name of the challenge is SUPERHOT, which is a reference to the video game.

- Open the SUPERHOT file in any hex editor.
- It can be deduced that the entire file has been XOR'd by the ASCII string, "SUPERHOT". Use any tool to XOR the file again to get the original file. The two tools below were tested:
  - [Xorpy](https://github.com/ShawnDEvans/xorpy)
  - [Random StackExchange C binary](https://unix.stackexchange.com/questions/398481/xor-a-file-against-a-key) (if used, make sure the keyfile does not have an extra LF)
- Run `file` on the decrypted output. It's a Microsoft Disk Image (VHD) format, created for use with VirtualBox.
- Add a `.vhd` extension to the file.
- From here, the VHD can be optionally mounted to a Windows machine and its contents can be inspected. However, there's a slight catch with this, which I'll explain in a bit.
- The drive contains the contents of a MS-DOS installation, along with an interesting file named `LOG1.IRC`.
- Reading this IRC log, it is discovered that `SUPERHOT.EXE` was deleted from the directory, `C:\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\`.
- Nothing ever gets deleted permanently on MS-DOS (or Windows for that matter). In fact, MS-DOS has a built-in `UNDELETE` [command](https://web.csulb.edu/~murdock/undelete.html) which can restore the file :)
- Here's where the catch comes in. If you create a new file on the disk, there's a very certain chance that the sector where the deleted file was will get overwritten, resulting in a corrupted binary. And by mounting the VHD on a modern Windows machine, it will create a `System Volume Information` folder or other hidden files and the integrity of the VHD is lost.
- (This is why the hint has been included.)
- Assuming the VHD file is unmodified (or it has been replaced with a clean version), a new virtual machine can be created using either VirtualBox or VMware using the VHD file.
- After MS-DOS boots, navigate to the correct directory and restore the file.

```
C:\>cd SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT

C:\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT>UNDELETE SUPERHOT.EXE

UNDELETE - A delete protection facility
Copyright (C) 1987-1993 Central Point Software, Inc.
All rights reserved.

Directory: C:\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT
File Specifications: SUPERHOT.EXE

    Delete Sentry control file not found.

    Deletion-tracking file not found.

    MS-DOS directory contains   1 deleted files.
    Of those,   1 files may be recovered.

Using the MS-DOS directory method.

    ?UPERHOT EXE    16013  7-30-99  1:37p ...A  Undelete (Y/N)?Y
    Please type the first character for ?UPERHOT.EXE: S

File successfully undeleted.


C:\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT\SUPER\HOT>
```

- Now, just run `SUPERHOT.EXE` and get the flag after chanting SUPERHOT one last time.

```
uiuctf{R3sT0re_f0R_M0re}
```
