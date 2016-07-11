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
	"net"
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

func (d CinderDriver) parseOpts(r volume.Request) volumes.CreateOpts {
        opts := volumes.CreateOpts {}
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
        // for now we'll do this, but we should pass this in as option.
	opts.Description = "Docker volume."
        return opts
}

func (d CinderDriver) getByName(name string) (volumes.Volume, error) {
	log.Debug("getVolByName: ", name)
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
	                        log.Debug("Found Volume ID: ", vol.ID)
				return true, nil
			}
		}
	        log.Error("Volume Not Found!")
		return false, nil
	})
	if err != nil {
	        log.Error("Extract Volume Error!")
		return volumes.Volume{}, errors.New("Not Found")
	}

	return vol, nil
}

// Create is part of the core Docker API and is called to instruct the plugin
//   that the user wants to create a volume, given a user specified volume name.
func (d CinderDriver) Create(r volume.Request) volume.Response {
	// TODO(jdg): Right now we have a weird mix for some of our semantics.  We
	// wanted to be able to dynamically create, but create can be called when a
	// volume already exists and is going to be used on another Docker node (ie
	// things like compose; we need to look at reworking things to NOT use
	// names to access Cinder volumes or some way to differentiate a create vs
	// a "use"
	log.Infof("Create volume %s on %s", r.Name, "Cinder")
	d.Mutex.Lock()
	defer d.Mutex.Unlock()
	vol, err := d.getByName(r.Name)
	if err != nil {
		log.Debugf("Found existing Volume by Name: %s", vol)
		return volume.Response{}
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
                log.Fatal("Failed to create Mount directory: %v", err)
        }
	return volume.Response{}
}

// Remove is part of the core Docker API and is called to Delete the specified
//   volume from disk
func (d CinderDriver) Remove(r volume.Request) volume.Response {
	log.Info("Remove/Delete Volume: ", r.Name)
	// TODO(ebalduf): Check error code
	vol, err := d.getByName(r.Name)
	log.Debugf("Remove/Delete Volume ID: %s", vol.ID)
	if err != nil {
		log.Errorf("Failed to retrieve volume named: ", r.Name, "during Remove operation", err)
		return volume.Response{Err: err.Error()}
	}
	errRes := volumes.Delete(d.Client, vol.ID)
	if errRes.Err != nil {
		log.Errorf("Failed to Delete volume: %s\nEncountered error: %s", vol, errRes)
	}
        path := filepath.Join(d.Conf.MountPoint, r.Name)
        if err := os.Remove(path); err != nil {
                log.Error("Failed to remove Mount directory: %v", err)
        }
	return volume.Response{}
}

// Mount is part of the core Docker API and is called to provide a volume,
//   given a user specified volume name. This is called once per container
//   start. If the same volume_name is requested more than once, the plugin may
//   need to keep track of each new mount request and provision at the first
//   mount request and deprovision at the last corresponding unmount request.
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
	volumeactions.Reserve(d.Client, vol.ID)

	iface := d.Conf.InitiatorIFace
	netDev, _ := net.InterfaceByName(iface)
	IPs, _ := net.InterfaceAddrs()
        log.Debugf("iface: %+v\n Addrs: %+v", netDev, IPs)
        initiator, err := GetInitiatorIqns()
	if err != nil {
		log.Error("Failed to retrieve Initiator name!")
		return volume.Response{ Err : err.Error() }
	}
	connectorOpts := volumeactions.ConnectorOpts{
		IP:        removeNetmask(IPs[int(netDev.Index)-1].String()),
		Host:      hostname,
		// TODO(ebalduf): Change assumption that we have only one Initiator defined
		Initiator: initiator[0],
		Wwpns:     []string{},
		Wwnns:     "",
		Multipath: false,
		Platform:  "x86",
		OSType:    "linux",
	}
	response := volumeactions.InitializeConnection(d.Client, vol.ID, &connectorOpts)
	data := response.Body.(map[string]interface{})["connection_info"].(map[string]interface{})["data"]
	log.Debugf("Init connection response data: %+v", data)
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
	if mountErr := Mount(device, d.Conf.MountPoint + "/" + r.Name); mountErr != nil {
		err := errors.New("Problem mounting docker volume ")
		log.Error(err)
		return volume.Response{Err: err.Error()}
	}

                path = filepath.Join(d.Conf.MountPoint, r.Name)
		attachOpts := volumeactions.AttachOpts{
			MountPoint:   path,
			InstanceUUID: d.Conf.HostUUID,
			HostName:     hostname,
			Mode:         "rw"}
		volumeactions.Attach(d.Client, vol.ID, &attachOpts)

	log.Debug("Response: ", d.Conf.MountPoint + "/" + r.Name)
	return volume.Response{Mountpoint: d.Conf.MountPoint + "/" + r.Name}
}

// Unmount is part of the core Docker API and is called to indicate that Docker
//   no longer is using the named volume. This is called once per container
//   stop. Plugin may deduce that it is safe to deprovision it at this point.
func (d CinderDriver) Unmount(r volume.Request) volume.Response {
	log.Infof("Unmounting volume: %+v", r)
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

	// Disconnect the iscsi target from the client
	tgt, portal := getTgtFromMountPoint(d.Conf.MountPoint + "/" + r.Name)
        iscsiDetachVolume(tgt, portal)
	// unreserve
        log.Debug("Unreserve")
        volumeactions.Unreserve(d.Client, vol.ID)

	// terminate_connection
        log.Debug("Terminate Connection")
	iface := d.Conf.InitiatorIFace
	netDev, _ := net.InterfaceByName(iface)
	IPs, _ := net.InterfaceAddrs()
	log.Debugf("iface: %+v\n Addrs: %+v", netDev, IPs)
	initiator, err := GetInitiatorIqns()
	if err != nil {
		log.Error("Failed to retrieve Initiator name!")
		return volume.Response{ Err : err.Error() }
	}
	hostname, _ := os.Hostname()
	connectorOpts := volumeactions.ConnectorOpts{
		IP:        removeNetmask(IPs[int(netDev.Index)-1].String()),
		Host:      hostname,
		// TODO(ebalduf): Change assumption that we have only one Initiator defined
		Initiator: initiator[0],
		Wwpns:     []string{},
		Wwnns:     "",
		Multipath: false,
		Platform:  "x86",
		OSType:    "linux",
	}
        volumeactions.TerminateConnection(d.Client, vol.ID, &connectorOpts)

	// detach
        log.Debug("Detach")
        volumeactions.Detach(d.Client, vol.ID)
	return volume.Response{}
}

// Path is part of the core Docker API and is called to remind Docker of the
//   path to the volume on the host.
func (d CinderDriver) Path(r volume.Request) volume.Response {
	log.Info("Retrieve path info for volume: ", r.Name)
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	return volume.Response{ Mountpoint: path, }
}

/* We'll need/want this for Docker 1.12
// Capabilities is part of the core Docker API and is called to determine if the
//   volume is globally accessible for not.
func (d CinderDriver) Capabilities(r volume.Request) volume.Response {
        return volume.Response{Capabilities: volume.Capability{Scope: "global"}}
}
*/

// Get is part of the core Docker API and is called to get the volume info
func (d CinderDriver) Get(r volume.Request) volume.Response {
	log.Info("Get volume: ", r.Name)
	v, err := d.getStatus(r)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	return volume.Response{ Volume: v, }
}

func (d CinderDriver) getStatus(r volume.Request) (*volume.Volume, error) {
	path := filepath.Join(d.Conf.MountPoint, r.Name)
	log.Debugf("Getting status for volume '%s'", path)

	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
                log.Debug("Path does not exist.")
		return nil, err
	}
	if fi == nil {
                log.Error("Path, could not stat error!")
		return nil, errors.New("Could not stat ")
	}

	volume := &volume.Volume{
		Name:       r.Name,
		Mountpoint: path}
	return volume, nil
}

// List is part of the core Docker API and is called to is the volumes
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
