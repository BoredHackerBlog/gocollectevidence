# gocollectevidence
Evidence collector (similar to cylr but worse) written in golang

(You can find cylr here: https://github.com/orlikoski/CyLR)

Evidence zip file and registry dump (if -savehklm is used) will need to be deleted manually by you after evidence is uploaded or copied.

# Compiling
1. You need Golang installed
2. Run `go get golang.org/x/sys/windows/registry`
3. Run `go get golang.org/x/crypto/ssh`
4. Run `github.com/pkg/sftp`
5. Run `go build` in the repo directory to get an executable

# Args
1. -h, to get help
2. -debug to see debug messages (optional)
3. -evidencezip filename.zip to rename the evidence zip file, default is evidence.zip (optional)
4. for sftp: -sftpserver, -sftpuser, -sftppass, -sftpkey, -sftpport (optional)
5. -savehklm this executes reg save command to dump sam, software, security, and system to C:\Windows\Temp\ (optional)

# Files/Folders collected
```
For the system:
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\SchedLgU.Txt", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Tasks", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Prefetch", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\inf\\setupapi.dev.log", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\drivers\\etc\\hosts", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\sru", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\winevt\\logs", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\Tasks", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\LogFiles\\W3SVC1", SYSTEMROOT))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Microsoft\\Search\\Data\\Applications\\Windows", PROGRAMDATA))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", PROGRAMDATA))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\$Recycle.Bin", SystemDrive))

For each User:
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\Explorer", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\WebCache\\", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\ConnectedDevicesPlatform", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt", userprofiledir))
evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", userprofiledir))
```
