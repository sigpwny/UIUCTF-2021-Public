# Tablet 3 solution

- After some enumeration, you should discover that the WebSSH app is installed.
- Use a SQLite database viewer to open `private/var/mobile/Containers/Data/Application/AA7DB282-D12B-4FB1-8DD2-F5FEF3E3198B/Library/Application Support/webssh.db`.
- Extract the SSH server IP, port, username, private key, and passphrase.
- Connect to the SSH server.
- Do enumeration to find the flag on the system.

```
uiuctf{upload_task_only_takes_9_seconds_0bf79b}
```
