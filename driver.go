package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/mitchellh/mapstructure"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
	"github.com/rackspace/gophercloud/openstack/blockstorage/v2/volumes"
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

func (d CinderDriver) getByName(name string) (volumes.Volume, error) {
	log.Info("getVolByName: ", name)
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
	        log.Error("Volume Not Found!")
		return false, nil
	})
	if err != nil {
	        log.Error("Extract Volume Error!")
		//return volumes.Volume{}, nil
		return volumes.Volume{}, errors.New("Not Found")
	}
	log.Info("Found Volume ID: ", vol.ID)

	return vol, nil
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
	//vol, err := volumes.Get(d.Client, r.Name).Extract()
	vol, err := d.getByName(r.Name)
	if err != nil {
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

	_, err = volumes.Create(d.Client, opts).Extract()
        path := filepath.Join(d.Conf.MountPoint, r.Name)
        // TODO(ebalduf) check for errors
        os.Mkdir(path, os.ModeDir)
	return volume.Response{}
}

func (d CinderDriver) Remove(r volume.Request) volume.Response {
	log.Info("Remove/Delete Volume: ", r.Name)
	//vol, err := volumes.Get(d.Client, volid.ID).Extract()
	vol, err := d.getByName(r.Name)
	log.Info("Remove/Delete Volume ID: ", vol.ID)
	if err != nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Remove operation", err)
		return volume.Response{Err: err.Error()}
	}
	errRes := volumes.Delete(d.Client, vol.ID)
	if errRes.Err != nil {
		log.Errorf("Failed to Delete volume: %s\nEncountered error: %s", vol, errRes)
	}
        // TODO(ebalduf) check for errors
        path := filepath.Join(d.Conf.MountPoint, r.Name)
        os.Remove(path)
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
	//vol, err := volumes.Get(d.Client, r.Name).Extract()
	vol, err := d.getByName(r.Name)
	if err != nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Mount operation", err)
		return volume.Response{Err: err.Error()}
	}
	volumeactions.Reserve(d.Client, vol.ID)

	//iface := d.Conf.InitiatorIFace
	//netDev, _ := net.InterfaceByName(iface)
	//IP, _ := netDev.Addrs()
	hostname, _ := os.Hostname()
	connectorOpts := volumeactions.ConnectorOpts{
		IP:        "192.168.59.103",
		Host:      hostname,
		Initiator: "iqn.1993-08.org.debian:01:26c57bde759c",
		Wwpns:     []string{},
		Wwnns:     "",
		Multipath: false,
		Platform:  "x86",
		OSType:    "linux",
	}
	response := volumeactions.InitializeConnection(d.Client, vol.ID, &connectorOpts)
	data := response.Body.(map[string]interface{})["connection_info"].(map[string]interface{})["data"]
	log.Info("Init connection response data: ", data)
	var con ConnectorInfo
	mapstructure.Decode(data, &con)
	path, device, err := attachVolume(&con, "default")
	log.Info("iSCSI connection done")
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
	if mountErr := Mount(device, d.Conf.MountPoint + "/" + r.Name); mountErr != nil {
		err := errors.New("Problem mounting docker volume ")
		log.Error(err)
		return volume.Response{Err: err.Error()}
	}

                path = filepath.Join(d.Conf.MountPoint, r.Name)
		attachOpts := volumeactions.AttachOpts{
			MountPoint:   path,
			//InstanceUUID: d.Conf.HostUUID,
			HostName:     "docker@" + hostname,
			Mode:         "rw"}
		volumeactions.Attach(d.Client, vol.ID, &attachOpts)

	log.Info("Response: ", d.Conf.MountPoint + "/" + r.Name)
	return volume.Response{Mountpoint: d.Conf.MountPoint + "/" + r.Name}
}

func (d CinderDriver) Unmount(r volume.Request) volume.Response {
	log.Info("Unmounting volume: ", r.Name)
        d.Mutex.Lock()
        defer d.Mutex.Unlock()
        vol, err := d.getByName(r.Name)
        if err != nil {
                log.Errorf("Failed to retrieve volume named: ", r.Name, "during Unmount operation", err)
                return volume.Response{Err: err.Error()}
        }

	if umountErr := Umount(d.Conf.MountPoint + "/" + r.Name); umountErr != nil {
		err := errors.New("Problem Unmounting docker volume ")
		log.Error(err)
		return volume.Response{Err: err.Error()}
	}
        // TODO(ebalduf) find a better way to get the portal information again
        hostname, _ := os.Hostname()
        connectorOpts := volumeactions.ConnectorOpts{
                IP:        "192.168.59.103",
                Host:      hostname,
                Initiator: "iqn.1993-08.org.debian:01:26c57bde759c",
                Wwpns:     []string{},
                Wwnns:     "",
                Multipath: false,
                Platform:  "x86",
                OSType:    "linux",
        }
	response := volumeactions.InitializeConnection(d.Client, vol.ID, &connectorOpts)
	data := response.Body.(map[string]interface{})["connection_info"].(map[string]interface{})["data"]
	log.Info("Init connection again to get the portal data: ", data)
	var con ConnectorInfo
	mapstructure.Decode(data, &con)
        detachVolume(&con)
	// unreserve
        log.Info("Unreserve")
        volumeactions.Unreserve(d.Client, vol.ID)
	// terminate_connection
        log.Info("Terminate Connection")
        volumeactions.TerminateConnection(d.Client, vol.ID, &connectorOpts)
        //data := response.Body.(map[string]interface{})["connection_info"].(map[string]interface{})["data"]
	// detach
        log.Info("Detach")
        volumeactions.Detach(d.Client, vol.ID)
	return volume.Response{}
}

// Get is part of the core Docker API and is called to return the filesystem path to a docker volume
func (d CinderDriver) Get(r volume.Request) volume.Response {
	log.Info("Get volume: ", r.Name)
	v, err := d.getPath(r)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	return volume.Response{
		Volume: v,
	}
}

func (d CinderDriver) getPath(r volume.Request) (*volume.Volume, error) {
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	log.Debugf("Getting path for volume '%s'", path)

	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
                log.Error("Path stat error.")
		return nil, err
	}
	if fi == nil {
                log.Error("Path doesn't exist!")
		return nil, errors.New("Could not stat ")
	}

	volume := &volume.Volume{
		Name:       r.Name,
		Mountpoint: path}
	return volume, nil
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
	path = "/dev/disk/by-path/ip-" + c.TgtPortal + "-iscsi-" + c.TgtIQN + "-lun-" + strconv.Itoa(c.TgtLun)

	if iscsiSupported() == false {
		err := errors.New("Unable to attach, open-iscsi tools not found on host")
		log.Error(err)
		return path, device, err
	}

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
