# gocollectevidence
Evidence collector (similar to cylr but worse) written in golang

(You can find cylr here: https://github.com/orlikoski/CyLR)

# Compiling
1. You need Golang installed
2. Get the Registry package golang.org/x/sys/windows/registry run `go get golang.org/x/sys/windows/registry`
3. Run `go build` in the repo directory to get an executable

# Args
1. -h, to get help
2. -debug to see debug messages (optional)
3. -evidencezip filename.zip to rename the evidence zip file, default is evidence.zip (optional)

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
