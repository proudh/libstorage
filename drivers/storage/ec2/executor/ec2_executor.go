package executor

import (
	"bufio"
	"io/ioutil"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"github.com/akutz/gofig"
	"github.com/akutz/goof"

	"github.com/emccode/libstorage/api/registry"
	"github.com/emccode/libstorage/api/types"
	"github.com/emccode/libstorage/drivers/storage/ec2"
)

// driver is the storage executor for the ec2 storage driver.
type driver struct {
	config         gofig.Config
	nextDeviceInfo *types.NextDeviceInfo
}

func init() {
	registry.RegisterStorageExecutor(ec2.Name, newDriver)
}

func newDriver() types.StorageExecutor {
	return &driver{}
}

func (d *driver) Init(ctx types.Context, config gofig.Config) error {
	d.config = config
	d.nextDeviceInfo = &types.NextDeviceInfo{
		Prefix:  "xvd",
		Pattern: "[a-z]",
		Ignore:  false,
	}

	return nil
}

func (d *driver) Name() string {
	return ec2.Name
}

// InstanceID returns the local instance ID for the test
func InstanceID() (*types.InstanceID, error) {
	return newDriver().InstanceID(nil, nil)
}

// InstanceID returns the aws instance configuration
func (d *driver) InstanceID(
	ctx types.Context,
	opts types.Store) (*types.InstanceID, error) {
	res, err := http.Get("http://169.254.169.254/latest/meta-data/instance-id/")
	if err != nil {
		return nil, goof.WithError("ec2 instance id lookup failed", err)
	}
	instanceID, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, goof.WithError("error reading ec2 instance id", err)
	}

	iid := &types.InstanceID{Driver: ec2.Name}
	if err := iid.MarshalMetadata(string(instanceID)); err != nil {
		return nil, goof.WithError("error marshalling instance id", err)
	}

	return iid, nil
}

// NextDevice returns the next available device.
func (d *driver) NextDevice(
	ctx types.Context,
	opts types.Store) (string, error) {
	letters := []string{
		"a", "b", "c", "d", "e", "f", "g", "h",
		"i", "j", "k", "l", "m", "n", "o", "p"}

	localDeviceNames := make(map[string]bool)

	localDevices, err := d.LocalDevices(
		ctx, &types.LocalDevicesOpts{Opts: opts})
	if err != nil {
		return "", err
	}
	localDeviceMapping := localDevices.DeviceMap

	for localDevice, _ := range localDeviceMapping {
		re, _ := regexp.Compile(`^/dev/` +
			d.nextDeviceInfo.Prefix +
			`(` + d.nextDeviceInfo.Pattern + `)`)
		res := re.FindStringSubmatch(localDevice)
		if len(res) > 0 {
			localDeviceNames[res[1]] = true
		}
	}

	for _, letter := range letters {
		if !localDeviceNames[letter] {
			nextDeviceName := "/dev/" +
				d.nextDeviceInfo.Prefix + letter
			return nextDeviceName, nil
		}
	}
	return "", goof.New("No available device")
}

func (d *driver) LocalDevices(
	ctx types.Context,
	opts *types.LocalDevicesOpts) (*types.LocalDevices, error) {

	out, err := exec.Command(
		"df", "--output=source,target").Output()
	if err != nil {
		return nil, goof.WithError("error running df", err)
	}

	input := string(out)

	re, _ := regexp.Compile(`^/dev/xvd([a-z])`)
	localDevices := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(input))
	// Set the split function for the scanning operation.
	scanner.Split(bufio.ScanWords)

	var prev string
	matched := false
	for scanner.Scan() {
		temp := scanner.Text()
		if matched {
			localDevices[prev] = temp
		}
		matched = re.MatchString(temp)
		prev = temp
	}

	return &types.LocalDevices{
		Driver:    ec2.Name,
		DeviceMap: localDevices,
	}, nil
}

/*
// SubnetResolver defines interface that can resolve subnet from environment
type SubnetResolver interface {
	ResolveSubnet() (string, error)
}

// AwsVpcSubnetResolver is thin interface that resolves instance subnet from
// ec2metadata service. This helper is used instead of bringing AWS SDK to
// executor on purpose to keep executor dependencies minimal.
type AwsVpcSubnetResolver struct {
	ec2MetadataIPAddress string
}

// ResolveSubnet determines VPC subnet id on running AWS instance
func (r *AwsVpcSubnetResolver) ResolveSubnet() (string, error) {
	resp, err := http.Get(r.getURL("mac"))
	if err != nil {
		return "", err
	}
	mac, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	resp, err = http.Get(r.getURL(fmt.Sprintf("network/interfaces/macs/%s/subnet-id", mac)))
	if err != nil {
		return "", err
	}
	subnetID, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	return string(subnetID), nil
}

func (r *AwsVpcSubnetResolver) getURL(path string) string {
	return fmt.Sprintf("http://%s/latest/meta-data/%s", r.ec2MetadataIPAddress, path)
}

// NewAwsVpcSubnetResolver creates AwsVpcSubnetResolver for default AWS endpoint
func NewAwsVpcSubnetResolver() *AwsVpcSubnetResolver {
	return &AwsVpcSubnetResolver{
		ec2MetadataIPAddress: "169.254.169.254",
	}
}*/
