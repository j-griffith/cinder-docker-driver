package main

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v2/volumes"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func removeNetmask(fulladdr string) string {
	wordcount := 0
	for i := range fulladdr {
		if fulladdr[i] != '/' {
			wordcount++
		} else {
			break
		}
	}
	return fulladdr[0:wordcount]
}

func GetInitiatorIqns() ([]string, error) {
	var iqns []string
	out, err := exec.Command("sudo", "cat", "/etc/iscsi/initiatorname.iscsi").CombinedOutput()
	log.Debugf("output and err from cat... %s, %s", out, err)
	if err != nil {
		log.Error("Error encountered gathering initiator names: ", err)
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		log.Debugf("Inspect line: %s", l)
		if strings.Contains(l, "InitiatorName=") {
			iqns = append(iqns, strings.Split(l, "=")[1])
		}
	}
	log.Debugf("Found the following iqns: %s", iqns)
	return iqns, nil
}

func waitForPathToExist(fileName string, numTries int) bool {
	log.Info("Waiting for path")
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
	log.Debug("Begin utils.getDeviceFileFromIscsiPath: ", iscsiPath)
	out, err := exec.Command("sudo", "ls", "-la", iscsiPath).CombinedOutput()
	if err != nil {
		return
	}
	d := strings.Split(string(out), "../../")
	log.Debugf("Found device: %s", d)
	devFile = "/dev/" + d[1]
	devFile = strings.TrimSpace(devFile)
	log.Debug("using base of: ", devFile)
	return
}

func getTgtInfo(v volumes.Volume) (target string, portal string) {
	out, err := exec.Command("sudo", "ls", "-l", "/dev/disk/by-path").CombinedOutput()
	if err != nil {
		log.Error("Failed to list contents of /dev/disk/by-path/: ", err)
		return
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, v.ID) {
			target = strings.Split((strings.Split(line, "-iscsi-")[1]), "-lun-")[0]
			portal = strings.Split((strings.Split(line, " ip-")[1]), "-iscsi-")[0]
		}
	}
	return
}

func getTgtFromMountPoint(mountpoint string) (target string, portal string) {
	log.Infof("Get iSCSI target for path %s", mountpoint)
	out, err := exec.Command("sudo", "df", "--output=source", mountpoint).CombinedOutput()
	if err != nil {
		log.Error("Failed to obtain device info from df cmd: ", err)
		return
	}

	device := "../../" + strings.Split(strings.Fields(string(out))[1], "/")[2]
	log.Debug("Formed the device: ", device)
	out, err = exec.Command("sudo", "ls", "-l", "/dev/disk/by-path").CombinedOutput()
	if err != nil {
		log.Error("Failed to list contents of /dev/disk/by-path/: ", err)
		return
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		log.Debugf("check line %s for %s...", line, device)
		if strings.Contains(line, device) {
			target = strings.Split((strings.Split(line, "-iscsi-")[1]), "-lun-")[0]
			portal = strings.Split((strings.Split(line, " ip-")[1]), "-iscsi-")[0]
		}
	}
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
	if err != nil {
		log.Warningf("Unmount call returned error: %s (%s)", err, out)
		if strings.Contains(string(out), "not mounted") {
			log.Debug("Ignore request for unmount on unmounted volume")
			err = errors.New("Volume is not mounted")
		}
	}
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
	log.Debugf("Create the node entry using args:  %+v", args)

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

	log.Debug("Update username to: ", username)
	authUserArgs := append(args, []string{"--op=update", "--name", "node.session.auth.username", "--value=" + username}...)
	if _, err := exec.Command("iscsiadm", authUserArgs...).CombinedOutput(); err != nil {
		log.Error(os.Stderr, "Error running iscsiadm set authuser: ", err)
		return err
	}

	log.Debug("Update password to: ", password)
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
	log.Infof("Logged into iSCSI target without error: %+v", loginArgs)
	return nil
}

func getDefaultIFace() (string, error) {
	cmd := "ip route get 8.8.8.8 | head -1 | cut -d ' ' -f5"
	iface, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		log.Errorf("Error detecting default iface: %s", cmd)
		log.Errorf("%s", err)
		return "", err
	} else {
		return string(iface), nil
	}

	return string(iface), nil
}

func getIPv4ForIFace(ifname string) (string, error) {
	interfaces, _ := net.Interfaces()
	if ifname == "default" {
		ifname, _ = getDefaultIFace()
	}

	for _, inter := range interfaces {
		if inter.Name == ifname {
			if addrs, err := inter.Addrs(); err == nil {
				for _, addr := range addrs {
					switch ip := addr.(type) {
					case *net.IPNet:
						if ip.IP.DefaultMask() != nil {
							return ip.IP.String(), nil
						}
					}
				}
			}
		}
	}
	return "", nil
}

func getRootDiskUUID() (string, error) {
	cmd := "mount | grep \" / \"|cut -d' ' -f 1"
	device, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		log.Errorf("Error detecting root disk: %s (%s)", cmd, device)
		return "", err
	}

	cmd = fmt.Sprintf("blkid %s|cut -d' ' -f2", device)
	uuidString, _ := exec.Command("sh", "-c", cmd).Output()
	uuid := strings.Split(string(uuidString), "UUID=\"")[1]
	uuid = strings.Split(string(uuid), " ")[0]
	uuid = strings.Replace(uuid, "\"", " ", -1)
	return uuid, nil
}
