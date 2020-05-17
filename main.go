//dont judge my code. it's only my 3rd golang project. 1st is not finished and i rm -rf'd the 2nd one.

package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
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

	HOSTNAME := os.Getenv("COMPUTERNAME")
	DOMAINNAME := os.Getenv("USERDOMAIN")

	defaultevidencezip := fmt.Sprintf("%s_%s.zip", HOSTNAME, DOMAINNAME)

	var evidencezip string
	flag.StringVar(&evidencezip, "evidencezip", defaultevidencezip, "Evidence Zip file")

	flag.BoolVar(&debug, "debug", false, "Turn on debugging messages")

	var sftpserver string
	var sftpport string
	var sftpuser string
	var sftppass string
	var sftpkey string
	flag.StringVar(&sftpserver, "sftpserver", "", "SFTP Server")
	flag.StringVar(&sftpport, "sftpport", "22", "SFTP Port")
	flag.StringVar(&sftpuser, "sftpuser", "", "SFTP Username")
	flag.StringVar(&sftppass, "sftppass", "", "SFTP Password")
	flag.StringVar(&sftpkey, "sftpkey", "", "SFTP Key")

	var savehklm bool
	flag.BoolVar(&savehklm, "savehklm", false, "run 'reg save' to save & collect HKLM SAM, SYSTEM, SECURITY, SOFTWARE. Saved to C:\\Windows\\Temp\\")

	flag.Parse()

	debugMsg(fmt.Sprintf("Evidence file name: %s", evidencezip))

	SYSTEMROOT := os.Getenv("SYSTEMROOT")
	PROGRAMDATA := os.Getenv("PROGRAMDATA")
	SystemDrive := os.Getenv("SystemDrive")

	var evidencelocationlist []string
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

	if savehklm {
		//dump SAM, SECURITY, SYSTEM, SOFTWARE
		//reg save HKLM\SAM C:\Windows\Temp\sam
		//HKLM\SECURITY SYSTEM SOFTWARE
		samfile := "C:\\Windows\\Temp\\sam"
		securityfile := "C:\\Windows\\Temp\\security"
		systemfile := "C:\\Windows\\Temp\\system"
		softwarefile := "C:\\Windows\\Temp\\software"

		savecmd := exec.Command("reg", "save", "HKLM\\SAM", samfile, "/y")
		err := savecmd.Run()
		if err != nil {
			fmt.Println(err)
		} else {
			evidencelocationlist = append(evidencelocationlist, samfile)
		}

		savecmd = exec.Command("reg", "save", "HKLM\\SECURITY", securityfile, "/y")
		err = savecmd.Run()
		if err != nil {
			fmt.Println(err)
		} else {
			evidencelocationlist = append(evidencelocationlist, securityfile)
		}

		savecmd = exec.Command("reg", "save", "HKLM\\SYSTEM", systemfile, "/y")
		err = savecmd.Run()
		if err != nil {
			fmt.Println(err)
		} else {
			evidencelocationlist = append(evidencelocationlist, systemfile)
		}

		savecmd = exec.Command("reg", "save", "HKLM\\SOFTWARE", softwarefile, "/y")
		err = savecmd.Run()
		if err != nil {
			fmt.Println(err)
		} else {
			evidencelocationlist = append(evidencelocationlist, softwarefile)
		}

	}

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
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\Explorer", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\Microsoft\\Windows\\WebCache\\", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Local\\ConnectedDevicesPlatform", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt", userprofiledir))
		evidencelocationlist = append(evidencelocationlist, fmt.Sprintf("%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\", userprofiledir))
	}

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
	flagmode := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	evidencezipfile, err := os.OpenFile(evidencezip, flagmode, 0777)
	if err != nil {
		debugMsg("Can't create a file")
	}
	defer evidencezipfile.Close()

	//https://www.golangprograms.com/go-program-to-compress-list-of-files-into-zip.html
	//zipwriter
	evidencezipwriter := zip.NewWriter(evidencezipfile)

	//add files to zip
	debugMsg("Adding files to the zip")

	for _, filepath := range filelisting {
		err = appendFiles(filepath, evidencezipwriter)
		if err != nil {
			fmt.Println(err)
		}

	}
	//https://www.ribice.ba/go-corrupt-archive/
	err = evidencezipwriter.Close()
	if err != nil {
		fmt.Println(err)
	}

	debugMsg("Done adding files to the zip")

	if (sftpserver != "" && sftpuser != "") && ((sftppass != "") || (sftpkey != "")) {

		debugMsg("Uploading files")

		sshauth := []ssh.AuthMethod{}

		if sftppass != "" {
			sshauth = []ssh.AuthMethod{ssh.Password(sftppass)}
		} else if sftpkey != "" {
			//key auth method has been not been tested
			//found somewhere on stackoverflow :D
			key, err := ioutil.ReadFile(sftpkey)
			if err != nil {
				log.Fatalf("Unable to read private key: %v", err)
			}
			signer, err := ssh.ParsePrivateKey(key)

			sshauth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
		}

		config := &ssh.ClientConfig{
			User:            sftpuser,
			Auth:            sshauth,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

		server := fmt.Sprintf("%s:%s", sftpserver, sftpport)
		conn, err := ssh.Dial("tcp", server, config)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		sftp, err := sftp.NewClient(conn)
		if err != nil {
			log.Fatal(err)
		}
		defer sftp.Close()

		dstFile, err := sftp.Create(evidencezip)
		if err != nil {
			log.Fatal(err)
		}
		defer dstFile.Close()

		srcFile, err := os.Open(evidencezip)
		if err != nil {
			log.Fatal(err)
		}
		_, err = io.Copy(dstFile, srcFile)
		if err != nil {
			log.Fatal(err)
		}
		debugMsg("Done copying to sftp. Feel free to delete the zip")
	}
}

