Warning: THIS CODE IS BROKEN, It chrashes after trying to read from File Explorer</br>
‎Note: If you are going to store data that you even have a hint of not wanting to loose, HAVE A BACKUP, This is not a reliable way of storing data.
# The Discord Data Project
This is a project, written in Python, that uses Discord bots to store files and mount a virtual disk. </br>
Main reason to not use it? It's really slow. (300KB/s - 7MB/s, it speeds up over time)
# Things to do
There's a lot of things to do, here they are, let me know if you find any more though/have any more ideas.
* It crashes after a few minutes: I figured out when it happens, it happens when you read from it in File Explorer. It will give a pop-up saying "Python Chrashed"
* It runs really slow: But, I know a way I can optimize it (It reuploads the entire file, just upload the changed chunks)
* Saving IDs and Permissions to a file: I have partially implemented this, its pretty simple to implement the rest though.
* Discord might not allow it: Based on the fact the limit can be anything winfspy can support, they might not like you are storing an entire datacenter on THEIR servers
# Basis
It is written in Python, and uses discord.py. </br>
(In Windows) It uses the winfspy library to mount everything as a virtual disk.
