package main

import (
	log "github.com/Sirupsen/logrus"
	"os"
	"os/exec"
	"strings"
	"time"
)

func GetInitiatorIqns() ([]string, error) {
	var iqns []string
	out, err := exec.Command("sudo", "cat", "/etc/iscsi/initiatorname.iscsi").CombinedOutput()
	if err != nil {
		log.Error("Error encountered gathering initiator names: ", err)
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.Contains(l, "InitiatorName=") {
			iqns = append(iqns, strings.Split(l, "=")[1])
		}
	}
	return iqns, nil
}

func waitForPathToExist(fileName string, numTries int) bool {
	for i := 0; i < numTries; i++ {
		_, err := os.Stat(fileName)
		if err == nil {
			log.Debug("path found: ", fileName)
			return true
		}
		if err != nil && !os.IsNotExist(err) {
			return false
		}
		time.Sleep(time.Second)
	}
	return false
}

func getDeviceFileFromIscsiPath(iscsiPath string) (devFile string) {
	log.Debug("Being utils.getDeviceFileFromIscsiPath: ", iscsiPath)
	out, err := exec.Command("sudo", "ls", "-la", iscsiPath).CombinedOutput()
	if err != nil {
		return
	}
	d := strings.Split(string(out), "../../")
	log.Debug("Found d: ", d)
	devFile = "/dev/" + d[1]
	log.Debug("using base of: ", devFile)
	devFile = strings.TrimSpace(devFile)
	return
}

func iscsiSupported() bool {
	_, err := exec.Command("iscsiadm", "-h").CombinedOutput()
	if err != nil {
		log.Debug("iscsiadm tools not found on this host")
		return false
	}
	return true
}

func iscsiDiscovery(portal string) (targets []string, err error) {
	log.Debugf("Begin utils.iscsiDiscovery (portal: %s)", portal)
	out, err := exec.Command("sudo", "iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", portal).CombinedOutput()
	if err != nil {
		log.Error("Error encountered in sendtargets cmd: ", out)
		return
	}
	targets = strings.Split(string(out), "\n")
	return

}

func iscsiLogin(tgt *ISCSITarget) (err error) {
	log.Debugf("Begin utils.iscsiLogin: %v", tgt)
	_, err = exec.Command("sudo", "iscsiadm", "-m", "node", "-p", tgt.Ip, "-T", tgt.Iqn, "--login").CombinedOutput()
	if err != nil {
		log.Errorf("Received error on login attempt: %v", err)
	}
	return err
}

func iscsiDisableDelete(tgt *ISCSITarget) (err error) {
	log.Debugf("Begin utils.iscsiDisableDelete: %v", tgt)
	_, err = exec.Command("sudo", "iscsiadm", "-m", "node", "-T", tgt.Iqn, "--portal", tgt.Ip, "-u").CombinedOutput()
	if err != nil {
		log.Debugf("Error during iscsi logout: ", err)
		//return
	}
	_, err = exec.Command("sudo", "iscsiadm", "-m", "node", "-o", "delete", "-T", tgt.Iqn).CombinedOutput()
	return
}

func GetFSType(device string) string {
	log.Debugf("Begin utils.GetFSType: %s", device)
	fsType := ""
	out, err := exec.Command("blkid", device).CombinedOutput()
	if err != nil {
		return fsType
	}

	if strings.Contains(string(out), "TYPE=") {
		for _, v := range strings.Split(string(out), " ") {
			if strings.Contains(v, "TYPE=") {
				fsType = strings.Split(v, "=")[1]
				fsType = strings.Replace(fsType, "\"", "", -1)
			}
		}
	}
	return fsType
}

func FormatVolume(device, fsType string) error {
	log.Debugf("Begin utils.FormatVolume: %s, %s", device, fsType)
	cmd := "mkfs.ext4"
	if fsType == "xfs" {
		cmd = "mkfs.xfs"
	}
	log.Debug("Perform ", cmd, " on device: ", device)
	out, err := exec.Command(cmd, "-F", device).CombinedOutput()
	log.Debug("Result of mkfs cmd: ", string(out))
	return err
}

func Mount(device, mountpoint string) error {
	log.Debugf("Begin utils.Mount device: %s on: %s", device, mountpoint)
	out, err := exec.Command("mkdir", mountpoint).CombinedOutput()
	out, err = exec.Command("mount", device, mountpoint).CombinedOutput()
	log.Debug("Response from mount ", device, " at ", mountpoint, ": ", string(out))
	if err != nil {
		log.Error("Error in mount: ", err)
	}
	return err
}

func Umount(mountpoint string) error {
	log.Debugf("Begin utils.Umount: %s", mountpoint)
	out, err := exec.Command("umount", mountpoint).CombinedOutput()
	log.Debug("Response from umount ", mountpoint, ": ", out)
	return err
}

func iscsiadmCmd(args []string) error {
	log.Debugf("Being utils.iscsiadmCmd: iscsiadm %+v", args)
	resp, err := exec.Command("iscsiadm", args...).CombinedOutput()
	if err != nil {
		log.Error("Error encountered running iscsiadm ", args, ": ", resp)
		log.Error("Error message: ", err)
	}
	return err
}

func LoginWithChap(tiqn, portal, username, password, iface string) error {
	args := []string{"-m", "node", "-T", tiqn, "-p", portal}
	createArgs := append(args, []string{"--interface", iface, "--op", "new"}...)

	if _, err := exec.Command("iscsiadm", createArgs...).CombinedOutput(); err != nil {
		log.Errorf("Error running iscsiadm %s", createArgs)
		log.Error(os.Stderr, "Error running iscsiadm node create: ", err)
		return err
	}

	authMethodArgs := append(args, []string{"--op=update", "--name", "node.session.auth.authmethod", "--value=CHAP"}...)
	if out, err := exec.Command("iscsiadm", authMethodArgs...).CombinedOutput(); err != nil {
		log.Error("Error running iscsiadm set authmethod: ", err, "{", out, "}")
		return err
	}

	authUserArgs := append(args, []string{"--op=update", "--name", "node.session.auth.username", "--value=" + username}...)
	if _, err := exec.Command("iscsiadm", authUserArgs...).CombinedOutput(); err != nil {
		log.Error(os.Stderr, "Error running iscsiadm set authuser: ", err)
		return err
	}
	authPasswordArgs := append(args, []string{"--op=update", "--name", "node.session.auth.password", "--value=" + password}...)
	if _, err := exec.Command("iscsiadm", authPasswordArgs...).CombinedOutput(); err != nil {
		log.Error(os.Stderr, "Error running iscsiadm set authpassword: ", err)
		return err
	}
	loginArgs := append(args, []string{"--login"}...)
	if _, err := exec.Command("iscsiadm", loginArgs...).CombinedOutput(); err != nil {
		log.Error(os.Stderr, "Error running iscsiadm login: ", err, loginArgs)
		return err
	}
	return nil
}
