package main

import (
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v2/extensions/volumeactions"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v2/volumes"
	"github.com/rackspace/gophercloud/pagination"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-plugins-helpers/volume"
)

type Config struct {
	DefaultVolSz   int //Default volume size in GiB
	MountPoint     string
	InitiatorIFace string //iface to use of iSCSI initiator
	HostUUID       string

	// Cinder credentials
	Endpoint    string
	Username    string
	Password    string
	TenantID    string
	InitiatorIP string
}

type CinderDriver struct {
	Client *gophercloud.ServiceClient
	Mutex  *sync.Mutex
	Conf   *Config
}

type ConnectorInfo struct {
	AccessMode string `mapstructure:"access_mode"`
	AuthUser   string `mapstructure:"auth_username"`
	AuthPass   string `mapstructure:"auth_password"`
	AuthMethod string `mapstructure:"auth_method"`
	TgtDisco   bool   `mapstructure:"target_discovered"`
	TgtIQN     string `mapstructure:"target_iqn"`
	TgtPortal  string `mapstructure:"target_portal"`
	VolumeID   string `mapstructure:"volume_id"`
	TgtLun     int    `mapstructure:"target_lun"`
	Encrypted  bool   `mapstructure:"encrypted"`
}

type ISCSITarget struct {
	Ip        string
	Port      string
	Portal    string
	Iqn       string
	Lun       string
	Device    string
	Discovery string
}

func processConfig(cfg string) (Config, error) {
	var conf Config
	content, err := ioutil.ReadFile(cfg)
	if err != nil {
		log.Fatal("Error reading config file: ", err)
	}
	err = json.Unmarshal(content, &conf)
	if err != nil {
		log.Fatal("Error parsing json config file: ", err)
	}

	if conf.MountPoint == "" {
		conf.MountPoint = "/var/lib/cinder/mount"
	}
	if conf.InitiatorIFace == "" {
		conf.InitiatorIFace = "default"
	}
	if conf.DefaultVolSz == 0 {
		conf.DefaultVolSz = 1
	}
	if conf.HostUUID == "" {
		conf.HostUUID, _ = getRootDiskUUID()
		log.Infof("Set node UUID to: %s", conf.HostUUID)
	}
	conf.InitiatorIP, _ = getIPv4ForIFace(conf.InitiatorIFace)
	log.Infof("Using config file: %s", cfg)
	log.Infof("Set InitiatorIFace to: %s", conf.InitiatorIFace)
	log.Infof("Set node InitiatorIP to: %s", conf.InitiatorIP)
	log.Infof("Set DefaultVolSz to: %d GiB", conf.DefaultVolSz)
	log.Infof("Set Endpoint to: %s", conf.Endpoint)
	log.Infof("Set Username to: %s", conf.Username)
	log.Infof("Set TenantID to: %s", conf.TenantID)
	return conf, nil
}

func New(cfgFile string) CinderDriver {
	conf, err := processConfig(cfgFile)
	if err != nil {
		log.Fatal("Error processing cinder driver config file: ", err)
	}

	_, err = os.Lstat(conf.MountPoint)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(conf.MountPoint, 0755); err != nil {
			log.Fatal("Failed to create Mount directory during driver init: %v", err)
		}
	}
	auth := gophercloud.AuthOptions{
		IdentityEndpoint: conf.Endpoint,
		Username:         conf.Username,
		Password:         conf.Password,
		TenantID:         conf.TenantID,
		AllowReauth:      true,
	}
	providerClient, err := openstack.AuthenticatedClient(auth)
	if err != nil {
		log.Fatal("Error initiating gophercloud provider client: ", err)
	}

	client, err := openstack.NewBlockStorageV2(providerClient,
		gophercloud.EndpointOpts{Region: "RegionOne"})
	if err != nil {
		log.Fatal("Error initiating gophercloud cinder client: ", err)
	}

	d := CinderDriver{
		Conf:   &conf,
		Mutex:  &sync.Mutex{},
		Client: client,
	}
	return d
}

func (d CinderDriver) parseOpts(r volume.Request) volumes.CreateOpts {
	opts := volumes.CreateOpts{}
	opts.Size = d.Conf.DefaultVolSz
	for k, v := range r.Options {
		log.Debugf("Option: %s = %s", k, v)
		switch k {
		case "size":
			vSize, err := strconv.Atoi(v)
			if err == nil {
				opts.Size = vSize
			}
		case "type":
			if r.Options["type"] != "" {
				opts.VolumeType = v
			}
		}
	}
	// We need to tag these volumes as being created by Docker *somewhere* so
	// we'll do it here.  In the future adding further descriptions is ok but
	// we should try and keep a tag of some sort here if we can
	opts.Description = "Docker volume."
	return opts
}

func (d CinderDriver) getByName(name string) (volumes.Volume, error) {
	log.Debug("getVolByName: `", name, "`")
	opts := volumes.ListOpts{Name: name}
	vols := volumes.List(d.Client, opts)
	var vol volumes.Volume
	err := vols.EachPage(func(page pagination.Page) (bool, error) {
		vList, err := volumes.ExtractVolumes(page)
		if err != nil {
			log.Errorf("Get Volume Error: %s", err)
			return false, err
		}

		for _, v := range vList {
			log.Debugf("querying volume: %+v\n", v)
			if v.Name == name {
				vol = v
				log.Debug("Found Volume ID: ", vol.ID)
				return true, nil
			}
		}
		log.Error("Volume Not Found!")
		return false, errors.New("Volume Not Found")
	})
	if err != nil {
		log.Errorf("Extract Volume Error: %s", err)
		return volumes.Volume{}, err
	}

	return vol, nil
}

func (d CinderDriver) Create(r volume.Request) volume.Response {
	// TODO(jdg): Right now we have a weird mix for some of our semantics.  We
	// wanted to be able to dynamically create, but create can be called when a
	// volume already exists and is going to be used on another Docker node (ie
	// things like compose); we need to look at reworking things to NOT use
	// names to access Cinder volumes or some way to differentiate a create vs
	// a "use"
	log.Infof("Create volume %s on %s", r.Name, "Cinder")
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	vol, err := d.getByName(r.Name)
	if err != nil {
		log.Errorf("Error getting existing Volume by Name: (volume %s, error %s)", vol, err.Error())
		return volume.Response{Err: err.Error()}
	}
	// FIXME(jdg): Keep in mind, NotFound isn't the only error we can get here,
	// we can also receive a "Multiple matches" error if there are duplicate
	// names.

	opts := d.parseOpts(r)
	opts.Name = r.Name
	log.Debugf("Creating with options: %+v", opts)

	_, err = volumes.Create(d.Client, opts).Extract()
	if err != nil {
		log.Errorf("Failed to Create volume: %s\nEncountered error: %s", r.Name, err)
		return volume.Response{Err: err.Error()}
	}
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	if err := os.Mkdir(path, os.ModeDir); err != nil {
		log.Errorf("Failed to create Mount directory: %v", err)
		return volume.Response{Err: err.Error()}
	}
	return volume.Response{}
}

func (d CinderDriver) Remove(r volume.Request) volume.Response {
	log.Info("Remove/Delete Volume: ", r.Name)
	vol, err := d.getByName(r.Name)
	log.Debugf("Remove/Delete Volume ID: %s", vol.ID)
	if err != nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Remove operation", err)
		return volume.Response{Err: err.Error()}
	}
	errRes := volumes.Delete(d.Client, vol.ID)
	log.Debugf("Response from Delete: %+v\n", errRes)
	if errRes.Err != nil {
		log.Errorf("Failed to Delete volume: %s\nEncountered error: %s", vol, errRes)
		log.Debugf("Error message: %s", errRes.ExtractErr())
		return volume.Response{Err: fmt.Sprintf("%s", errRes.ExtractErr())}
	}
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	if err := os.Remove(path); err != nil {
		log.Error("Failed to remove Mount directory: %v", err)
		return volume.Response{Err: err.Error()}
	}
	return volume.Response{}
}

func (d CinderDriver) Path(r volume.Request) volume.Response {
	log.Info("Retrieve path info for volume: `", r.Name, "`")
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	log.Debug("Path reported as: ", path)
	return volume.Response{Mountpoint: path}
}

func (d CinderDriver) Mount(r volume.Request) volume.Response {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()

	hostname, _ := os.Hostname()
	log.Infof("Mounting volume %+v on %s", r, hostname)
	vol, err := d.getByName(r.Name)
	if err != nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Mount operation", err)
		return volume.Response{Err: err.Error()}
	}
	if vol.ID == "" {
		log.Error("Volume Not Found!")
		err := errors.New("Volume Not Found")
		return volume.Response{Err: err.Error()}
	}
	if vol.Status == "creating" {
		// NOTE(jdg):  This may be a successive call after a create which from
		// the docker volume api can be quite speedy.  Take a short pause and
		// check the status again before proceeding
		time.Sleep(time.Second * 5)
		vol, err = d.getByName(r.Name)
	}

	if err != nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Mount operation", err)
		return volume.Response{Err: err.Error()}
	}

	if vol.Status != "available" {
		log.Debugf("Volume info: %+v\n", vol)
		log.Errorf("Invalid volume status for Mount request, volume is: %s but must be available", vol.Status)
		err := errors.New("Invalid volume status for Mount request")
		return volume.Response{Err: err.Error()}
	}
	volumeactions.Reserve(d.Client, vol.ID)

	iface := d.Conf.InitiatorIFace
	netDev, _ := net.InterfaceByName(iface)
	IPs, _ := net.InterfaceAddrs()
	log.Debugf("iface: %+v\n Addrs: %+v", netDev, IPs)

	log.Debug("Gather up initiator IQNs...")
	initiator, err := GetInitiatorIqns()
	if err != nil {
		log.Error("Failed to retrieve Initiator name!")
		return volume.Response{Err: err.Error()}
	}
	// TODO(ebalduf): Change assumption that we have only one Initiator defined
	log.Debugf("Value of IPs is=%+v\n", IPs)
	connectorOpts := volumeactions.ConnectorOpts{
		IP:        d.Conf.InitiatorIP,
		Host:      hostname,
		Initiator: initiator[0],
		Wwpns:     []string{},
		Wwnns:     "",
		Multipath: false,
		Platform:  "x86",
		OSType:    "linux",
	}
	log.Debug("Issue InitializeConnection...")
	response := volumeactions.InitializeConnection(d.Client, vol.ID, &connectorOpts)
	log.Debugf("Response from InitializeConnection: %+v\n", response)
	data := response.Body.(map[string]interface{})["connection_info"].(map[string]interface{})["data"]
	var con ConnectorInfo
	mapstructure.Decode(data, &con)
	path, device, err := attachVolume(&con, "default")
	log.Debug("iSCSI connection done")
	if path == "" || device == "" && err == nil {
		log.Error("Missing path or device, but err not set?")
		log.Debug("Path: ", path, " ,Device: ", device)
		return volume.Response{Err: err.Error()}

	}
	if err != nil {
		log.Errorf("Failed to perform iscsi attach of volume %s: %v", r.Name, err)
		return volume.Response{Err: err.Error()}
	}

	if GetFSType(device) == "" {
		//TODO(jdg): Enable selection of *other* fs types
		log.Debugf("Formatting device")
		err := FormatVolume(device, "ext4")
		if err != nil {
			err := errors.New("Failed to format device")
			log.Error(err)
			return volume.Response{Err: err.Error()}
		}
	}
	if mountErr := Mount(device, d.Conf.MountPoint+"/"+r.Name); mountErr != nil {
		err := errors.New("Problem mounting docker volume ")
		log.Error(err)
		return volume.Response{Err: err.Error()}
	}

	path = filepath.Join(d.Conf.MountPoint, r.Name)
	// NOTE(jdg): Cinder will barf if you provide both Instance and HostName
	// which is kinda silly... but it is what it is
	attachOpts := volumeactions.AttachOpts{
		MountPoint:   path,
		InstanceUUID: d.Conf.HostUUID,
		HostName:     "",
		Mode:         "rw"}
	log.Debug("Call gophercloud Attach...")
	attRes := volumeactions.Attach(d.Client, vol.ID, &attachOpts)
	log.Debugf("Attach results: %+v", attRes)
	return volume.Response{Mountpoint: d.Conf.MountPoint + "/" + r.Name}
}

func (d CinderDriver) Unmount(r volume.Request) volume.Response {
	log.Infof("Unmounting volume: %+v", r)
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	vol, err := d.getByName(r.Name)
	if vol.ID == "" {
		log.Errorf("Request to Unmount failed because volume `%s` could not be found", r.Name)
		err := errors.New("Volume Not Found")
		return volume.Response{Err: err.Error()}
	}

	if err != nil {
		log.Errorf("Failed to retrieve volume named: `", r.Name, "` during Unmount operation", err)
		return volume.Response{Err: err.Error()}
	}

	if umountErr := Umount(d.Conf.MountPoint + "/" + r.Name); umountErr != nil {
		if umountErr.Error() == "Volume is not mounted" {
			log.Warning("Request to unmount volume, but it's not mounted")
			return volume.Response{}
		} else {
			return volume.Response{Err: umountErr.Error()}
		}
	}
	// NOTE(jdg): So there's a couple issues with how Docker works here.  If
	// you are trying to attach and it fails, it kindly goes through and does
	// an Unmount to clean up anything that went bad, BUT that creates a
	// problem here.  Say for example you try to attach an in-use volume, we
	// don't want to rip that out from under wherever it's currently being used

	// NOTE(jdg): Don't rely on things like `df --output=source mounpoint`
	// that's no good for error situations.

	tgt, portal := getTgtInfo(vol)
	iscsiDetachVolume(tgt, portal)
	log.Debug("Terminate Connection")
	iface := d.Conf.InitiatorIFace
	netDev, _ := net.InterfaceByName(iface)
	IPs, _ := net.InterfaceAddrs()
	log.Debugf("iface: %+v\n Addrs: %+v", netDev, IPs)
	initiators, err := GetInitiatorIqns()
	if err != nil {
		log.Error("Failed to retrieve Initiator name!")
		return volume.Response{Err: err.Error()}
	}
	hostname, _ := os.Hostname()
	// TODO(ebalduf): Change assumption that we have only one Initiator defined
	// TODO(jdg): For now we're only supporting linux, but in the future we'll
	// need to get rid of the hard coded Platform/OSType and fix this up for
	// things like say Windows
	log.Debugf("IPs=%+v\n", IPs)
	connectorOpts := volumeactions.ConnectorOpts{
		IP:        d.Conf.InitiatorIP,
		Host:      hostname,
		Initiator: initiators[0],
		Wwpns:     []string{},
		Wwnns:     "",
		Multipath: false,
		Platform:  "x86",
		OSType:    "linux",
	}
	log.Debugf("Unreserve volume: %s", vol.ID)
	volumeactions.Unreserve(d.Client, vol.ID)
	log.Debugf("Terminate connection for volume: %s", vol.ID)
	volumeactions.TerminateConnection(d.Client, vol.ID, &connectorOpts)
	log.Debugf("Detach volume: %s", vol.ID)
	volumeactions.Detach(d.Client, vol.ID)
	return volume.Response{}
}

func (d CinderDriver) Capabilities(r volume.Request) volume.Response {
	return volume.Response{Capabilities: volume.Capability{Scope: "global"}}
}

func (d CinderDriver) Get(r volume.Request) volume.Response {
	log.Info("Get volume: ", r.Name)
	vol, err := d.getByName(r.Name)
	if err != nil {
		log.Errorf("Failed to retrieve volume `%s`: %s", r.Name, err.Error())
		return volume.Response{Err: err.Error()}
	}
	if vol.ID == "" {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Get operation", err)
		err = errors.New("Volume Not Found")
		return volume.Response{Err: err.Error()}
	}

	// NOTE(jdg): Volume can exist but not necessarily be attached, this just
	// gets the volume object and where it "would" be attached, it may or may
	// not currently be attached, but we don't care here
	path := filepath.Join(d.Conf.MountPoint, r.Name)

	return volume.Response{Volume: &volume.Volume{Name: r.Name, Mountpoint: path}}
}

func (d CinderDriver) List(r volume.Request) volume.Response {
	log.Info("List volumes: ", r.Name)
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	var vols []*volume.Volume
	pager := volumes.List(d.Client, volumes.ListOpts{})
	pager.EachPage(func(page pagination.Page) (bool, error) {
		vlist, _ := volumes.ExtractVolumes(page)
		for _, v := range vlist {
			vols = append(vols, &volume.Volume{Name: v.Name, Mountpoint: path})
		}
		return true, nil
	})
	return volume.Response{Volumes: vols}
}

func iscsiDetachVolume(tgt string, portal string) (err error) {
	target := &ISCSITarget{
		Ip:     portal,
		Portal: portal,
		Iqn:    tgt,
	}
	err = iscsiDisableDelete(target)
	return
}

func attachVolume(c *ConnectorInfo, iface string) (path, device string, err error) {
	log.Debugf("Connector is: %+v", c)
	path = "/dev/disk/by-path/ip-" + c.TgtPortal + "-iscsi-" + c.TgtIQN + "-lun-" + strconv.Itoa(c.TgtLun)

	if iscsiSupported() == false {
		err := errors.New("Unable to attach, open-iscsi tools not found on host")
		log.Error(err)
		return path, device, err
	}

	// Make sure it's not already attached
	if waitForPathToExist(path, 1) {
		log.Debug("Get device file from path: ", path)
		device = strings.TrimSpace(getDeviceFileFromIscsiPath(path))
		return path, device, nil
	}

	err = LoginWithChap(c.TgtIQN, c.TgtPortal, c.AuthUser, c.AuthPass, iface)
	if err != nil {
		log.Error(err)
		return path, device, err
	}
	if waitForPathToExist(path, 5) {
		device = strings.TrimSpace(getDeviceFileFromIscsiPath(path))
		log.Debugf("Attached volume at (path, devfile): %s, %s", path, device)
		return path, device, nil
	}
	return path, device, nil
}
