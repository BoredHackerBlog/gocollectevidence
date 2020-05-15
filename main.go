//dont judge my code. it's only my 3rd golang project. 1st is not finished and i rm -rf'd the 2nd one.

package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

var debug bool

func debugMsg(msg string) {
	if debug == true {
		fmt.Println(msg)
	}
}

func appendFiles(filename string, zipw *zip.Writer) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Failed to open %s: %s", filename, err)
	}
	defer file.Close()

	wr, err := zipw.Create(filename)
	if err != nil {
		msg := "Failed to create entry for %s in zip file: %s"
		return fmt.Errorf(msg, filename, err)
	}

	if _, err := io.Copy(wr, file); err != nil {
		return fmt.Errorf("Failed to write %s to zip: %s", filename, err)
	}

	return nil
}

func main() {
	SYSTEMROOT := os.Getenv("SYSTEMROOT")
	PROGRAMDATA := os.Getenv("PROGRAMDATA")
	SystemDrive := os.Getenv("SystemDrive")

	var evidencelocationlist []string
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\SchedLgU.Txt", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Tasks", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Prefetch", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\inf\\setupapi.dev.log", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Appcompat\\Programs", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\drivers\\etc\\hosts", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\sru", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\winevt\\logs", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\Tasks", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\LogFiles\\W3SVC1", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SAM", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SYSTEM", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SOFTWARE", SYSTEMROOT))
	///evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SECURITY", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SAM.LOG1", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SYSTEM.LOG1", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SOFTWARE.LOG1", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SECURITY.LOG1", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SAM.LOG2", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SYSTEM.LOG2", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SOFTWARE.LOG2", SYSTEMROOT))
	//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\System32\\config\\SECURITY.LOG2", SYSTEMROOT))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Microsoft\\Search\\Data\\Applications\\Windows", PROGRAMDATA))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", PROGRAMDATA))
	evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\$Recycle.Bin", SystemDrive))

	//https://github.com/Velocidex/evtx/blob/master/cmd/extract_windows.go
	//Go to Registry, get profile paths, append to list
	//Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList look at subkeys
	//look at FullProfile int and if exists then get ProfileImagePath
	var userprofiledirs []string

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		log.Fatal(err)
	}
	defer k.Close()
	subkeynames, err := k.ReadSubKeyNames(-1)
	if err != nil {
		log.Fatal(err)
	}
	for _, subkey := range subkeynames {
		k, err := registry.OpenKey(k, subkey, registry.QUERY_VALUE)
		defer k.Close()
		if err != nil {
			log.Fatal(err)
		}
		i, _, _ := k.GetIntegerValue("FullProfile")
		if i > 0 {
			i, _, _ := k.GetStringValue("ProfileImagePath")
			userprofiledirs = append(userprofiledirs, i)
		}
	}

	for _, userprofiledir := range userprofiledirs {
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent", userprofiledir))
		//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\NTUSER.DAT", userprofiledir))
		//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\NTUSER.DAT.LOG1", userprofiledir))
		//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\NTUSER.DAT.LOG2", userprofiledir))
		//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", userprofiledir))
		//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG1", userprofiledir))
		//evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat.LOG2", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\Explorer", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\WebCache\\", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\ConnectedDevicesPlatform", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", userprofiledir))
	}

	var evidencezip string
	flag.StringVar(&evidencezip, "evidencezip", "evidence.zip", "Evidence Zip file")

	flag.BoolVar(&debug, "debug", false, "Turn on debugging messages")

	flag.Parse()

	debugMsg(fmt.Sprintf("Evidence file name: %s", evidencezip))

	//get list of files from disk
	debugMsg("Finding all the files")
	var filelisting []string

	for _, evidencefilepath := range evidencelocationlist {
		err := filepath.Walk(evidencefilepath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() == false {
					filelisting = append(filelisting, path)
				}
				return nil
			})
		if err != nil {
			fmt.Println(err)
		}
	}

	if len(filelisting) == 0 {
		debugMsg("No files in the list. Exiting.")
		os.Exit(0)
	}

	debugMsg("Files found")
	for _, filepath := range filelisting {
		debugMsg(filepath)
	}

	//create zip file on disk
	flagmode := os.O_WRONLY | os.O_CREATE
	evidencezipfile, err := os.OpenFile(evidencezip, flagmode, 0777)
	if err != nil {
		debugMsg("Can't create a file")
	}
	defer evidencezipfile.Close()

	//https://www.golangprograms.com/go-program-to-compress-list-of-files-into-zip.html
	//zipwriter
	evidencezipwriter := zip.NewWriter(evidencezipfile)
	defer evidencezipwriter.Close()

	//add files to zip
	debugMsg("Adding files to the zip")

	for _, filepath := range filelisting {
		err = appendFiles(filepath, evidencezipwriter)
		if err != nil {
			fmt.Println(err)
		}

	}

}
