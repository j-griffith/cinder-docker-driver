package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v2/extensions/volumeactions"
	"github.com/rackspace/gophercloud/pagination"
	"io/ioutil"
	//"net"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/go-plugins-helpers/volume"
)

type Config struct {
	DefaultVolSz   int //Default volume size in GiB
	MountPoint     string
	InitiatorIFace string //iface to use of iSCSI initiator
	HostUUID       string

	// Cinder credentials
	Endpoint string
	Username string
	Password string
	TenantID string
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

func formatOpts(r volume.Request) {
	// NOTE(jdg): For now we just want to minimize issues like case usage for
	// the two basic opts most used (size and type).  Going forward we can add
	// all sorts of things here based on what we decide to add as valid opts
	// during create and even other calls
	for k, v := range r.Options {
		if strings.EqualFold(k, "size") {
			r.Options["size"] = v
		} else if strings.EqualFold(k, "type") {
			r.Options["type"] = v
		}
	}
}

func (d CinderDriver) getByName(name string) volumes.Volume {
	opts := volumes.ListOpts{Name: name}
	vols := volumes.List(d.Client, opts)
	var vol volumes.Volume
	err := vols.EachPage(func(page pagination.Page) (bool, error) {
		vList, err := volumes.ExtractVolumes(page)
		if err != nil {
			return false, err
		}

		for _, v := range vList {
			if v.Name == name {
				vol = v
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return volumes.Volume{}
	}

	return vol
}
func (d CinderDriver) Create(r volume.Request) volume.Response {
	// TODO(jdg): Right now we have a weird mix for some of our semantics.  We
	// wanted to be able to dynamically create, but create can be called when a
	// volume already exists and is going to be used on another Docker node (ie
	// things like compose; we need to look at reworking things to NOT use
	// names to access Cinder volumes or some way to differentiate a create vs
	// a "use"
	log.Infof("Create volume %s on %s\n", r.Name, "Cinder")
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	vol, err := volumes.Get(d.Client, r.Name).Extract()
	if vol != nil {
		log.Infof("Found existing Volume by Name: %s", vol)
		return volume.Response{}
	}
	// FIXME(jdg): Keep in mind, NotFound isn't the only error we can get here,
	// we can also receive a "Multiple matches" error if there are duplicate
	// names.
	vSize, err := strconv.Atoi(r.Options["size"])
	if err != nil {
		vSize = d.Conf.DefaultVolSz
	}
	opts := volumes.CreateOpts{
		Size: vSize,
		Name: r.Name,
	}
	if r.Options["type"] != "" {
		opts.VolumeType = r.Options["type"]
	}

	vol, err = volumes.Create(d.Client, opts).Extract()
	return volume.Response{}
}

func (d CinderDriver) Remove(r volume.Request) volume.Response {
	log.Info("Remove/Delete Volume: ", r.Name)
	vol, err := volumes.Get(d.Client, r.Name).Extract()
	if vol == nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Remove operation", err)
		return volume.Response{Err: err.Error()}
	}
	errRes := volumes.Delete(d.Client, vol.ID)
	if errRes.Err != nil {
		log.Errorf("Failed to Delete volume: %s\nEncountered error: %s", vol, errRes)
	}
	return volume.Response{}
}

func (d CinderDriver) Path(r volume.Request) volume.Response {
	log.Info("Retrieve path info for volume: ", r.Name)
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	log.Debug("Path reported as: ", path)
	return volume.Response{Mountpoint: path}
}

func (d CinderDriver) Mount(r volume.Request) volume.Response {
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	log.Infof("Mounting volume %s on %s\n", r.Name, "solidfire")
	vol, err := volumes.Get(d.Client, r.Name).Extract()
	if vol == nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Mount operation", err)
		return volume.Response{Err: err.Error()}
	}
	volumeactions.Reserve(d.Client, vol.ID)

	//iface := d.Conf.InitiatorIFace
	//netDev, _ := net.InterfaceByName(iface)
	//IP, _ := netDev.Addrs()
	//hostname, _ := os.Hostname()
	connectorOpts := volumeactions.ConnectorOpts{
		IP:        "192.168.0.29",
		Host:      "bdr73.solidfire.net",
		Initiator: "eth0",
		Wwpns:     "",
		Wwnns:     "",
		Multipath: false,
		Platform:  "x86",
		OSType:    "linux",
	}
	response := volumeactions.InitializeConnection(d.Client, vol.ID, &connectorOpts)
	data := response.Body.(map[string]interface{})["connection_info"].(map[string]interface{})["data"]
	var con ConnectorInfo
	mapstructure.Decode(data, &con)
	path, device, err := attachVolume(&con, "default")
	if path == "" || device == "" && err == nil {
		log.Error("Missing path or device, but err not set?")
		log.Debug("Path: ", path, ",Device: ", device)
		return volume.Response{Err: err.Error()}

	}
	if err != nil {
		log.Errorf("Failed to perform iscsi attach of volume %s: %v", r.Name, err)
		return volume.Response{Err: err.Error()}
	}
	log.Debugf("Attached volume at (path, devfile): %s, %s", path, device)
	/*
		attachOpts := volumeactions.AttachOpts{
			MountPoint:   d.Conf.MountPoint + r.Name,
			InstanceUUID: d.Conf.HostUUID,
			HostName:     "bdr73.solidfire.net",
			Mode:         "rw"}
		volumeactions.Attach(d.Client, vol.ID, &attachOpts)
	*/
	return volume.Response{Mountpoint: d.Conf.MountPoint + "/" + r.Name}
}

func (d CinderDriver) Unmount(r volume.Request) volume.Response {
	log.Info("Unmounting volume: ", r.Name)
	// unreserve
	// terminate_connection
	// detach
	return volume.Response{}
}

func (d CinderDriver) Get(r volume.Request) volume.Response {
	log.Info("Get volume: ", r.Name)
	vol, err := volumes.Get(d.Client, r.Name).Extract()
	if vol == nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Get operation", err)
		return volume.Response{Err: err.Error()}
	}
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

func detachVolume(c *ConnectorInfo) (err error) {
	tgt := &ISCSITarget{
		Ip:     c.TgtPortal,
		Portal: c.TgtPortal,
		Iqn:    c.TgtIQN,
	}
	err = iscsiDisableDelete(tgt)
	return
}

func attachVolume(c *ConnectorInfo, iface string) (path, device string, err error) {
	log.Infof("Connector is: %+v\n", c)
	path = "/dev/disk/by-path/ip-" + c.TgtPortal + "-iscsi-" + c.TgtIQN + "-lun-1"

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
		return path, device, nil
	}
	return path, device, nil
}
