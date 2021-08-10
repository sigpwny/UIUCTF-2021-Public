# Simply Perfect Solution

The process accounting format is specified [here](https://linux.die.net/man/5/acct).

The best way to view process accounting logs is through this command:  
`lastcomm --pid -f log | tac | nl -v 0 | less`

It displays the entries in order from oldest to most recent with line numbers and PIDs/PPIDs. 

The way to solve the challenge is to understand the description well. 

"You snuck into the building. You logged into the mainframe and checked a few things out."

This implies we logged onto the terminal with physical console access, or `tty1`. This is a field in a process accounting log, so we can find our activity from this clue. 

"Time ran out, but you gave yourself remote access before you got out."

This implies we logged out after a short while but we managed to add ourselves a backdoor for access later. 

To be completed...

(ian copying from discord)

there are three interactions by an attacker on a server

all of the processes executed on the server are logged

you have to clean all the logs of the three interactions

and also a periodic collection script

the first interaction is a tty1 via the console

the second interaction is with a netcat backdoor, so it's not tied with a tty/pty session

but it can be found by looking at unique commands since there is a crontab process during that session

there is an scp cronjob every 20 minutes for a while

so you have to clean that

the third interaction is with ssh and then you have to clean the logs from that

and there's a lot of activity based on me actually using the server and me trying to fake admin activity and generate logging lol

the flag is identifying the log entries and then literally just removing bytes associated with each log entry(edited)

and then the hash of the resulting log file is the flag
