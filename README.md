#Cinder Docker Driver


Docker Volume Plugin to enable consumption of OpenStack-Cinder Block Storage
with containers.

##Install

### Build From Source
```shell
git clone https://github.com/j-griffith/cinder-docker-driver
cd cinder-docker-driver
go build
sudo ./install.sh
```

###Just the bits
Use curl to download and run the install script in the package Github repo::

```shell
curl -sSl https://raw.githubusercontent.com/j-griffith/cinder-docker-driver/master/install.sh | sh
```
##Configuration options
Example config.json file:

```json
{
  Endpoint: "http://172.16.140.145:5000/v2.0",
  Username: "Fred",
  Password: "FredsPassWord",
  TenantID: "979ddb6183834b9993954ca6de518c5a"
}
```
###Minimal/Required Config
Configuration options are stored in json format in config.json, the minimum required options provide just enough info to connect to our Cinder API and execute commands.  Note that for quick demos and just trying things out you can use the default interface and network for your iSCSI connections, it's highly recommended however you don't do this if you want to do anything that might require some performance.

- Endpoint
- Username
- Password
- TenantID

###Additonal/Optional Config

- DefaultVolSz (1 GiB)
- MountPoint (/var/lib/cinder/mount)
- InitiatorIFace (default)
- HostUUID (root disk UUID)
- InitiatorIP (default interface IP)

Example config with additional options:

```json
{
  Endpoint: "http://172.16.140.145:5000/v2.0",
  Username: "Fred",
  Password: "FredsPassWord",
  TenantID: "979ddb6183834b9993954ca6de518c5a",
  DefaultVolSz: 1,
  MountPoint: "/mnt/cvols",
  InitiatorIFace: "/dev/eth4",
  HostUUID: "219b0670-a214-4281-8424-5bb3be109ddd",
  InitiatorIP: "192.168.4.201"
}
```
##Start the daemon
We don't have an init script yet, so for now, just launch the driver daemon as root or with sudo:

```shell
sudo cinder-docker-driver  >> /var/log/cdd.out 2>&1 &'
sudo service docker restart
```

##Try it out
Assuming your credentials were all set correctly and the driver was able to start up without any issues, you should be ready to go.

To get a list of commands offered via the Docker Volume API:

```console
$ docker volume --help

Usage: 	docker volume COMMAND

Manage Docker volumes

Options:
      --help   Print usage

Commands:
  create      Create a volume
  inspect     Display detailed information on one or more volumes
  ls          List volumes
  rm          Remove a volume

Run 'docker volume COMMAND --help' for more information on a command.
```

To create a volume and specify some options like size and Cinder Type:

```console
$ docker volume create -d cinder --name fredsFirstDVol -o size=10 -o type=lvm-1
```

You can also just add the volume arguments to your docker run command and Docker will make the create calls for you.  Keep in mind that if the volume already exists we'll just grab it and try to attach it, if it doesn't, the Docker service will issue a request to the driver to create it.


