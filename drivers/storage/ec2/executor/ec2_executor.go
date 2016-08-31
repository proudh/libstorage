package executor

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	//"os/exec"
	"regexp"
	"strings"

	"github.com/akutz/gofig"
	"github.com/akutz/goof"

	"github.com/emccode/libstorage/api/context"
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
		return "", goof.WithError("error getting local devices", err)
	}
	localDeviceMapping := localDevices.DeviceMap

	for localDevice := range localDeviceMapping {
		re, _ := regexp.Compile(`^/dev/` +
			d.nextDeviceInfo.Prefix +
			`(` + d.nextDeviceInfo.Pattern + `)`)
		res := re.FindStringSubmatch(localDevice)
		if len(res) > 0 {
			localDeviceNames[res[1]] = true
		}
	}

	ephemeralDevices, err := d.getEphemeralDevices()
	if err != nil {
		return "", goof.WithError("error getting ephemeral devices", err)
	}

	for _, ephemeralDevice := range ephemeralDevices {
		re, _ := regexp.Compile(`^` +
			d.nextDeviceInfo.Prefix +
			`(` + d.nextDeviceInfo.Pattern + `)`)
		res := re.FindStringSubmatch(ephemeralDevice)
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
	fmt.Printf("From LocalDevices: %#v\n", ctx)
	localDevices, ok := ctx.Value(context.LocalDevicesKey).(map[string]string)
	if !ok {
		return nil, goof.New("error getting local devices from context")
	}

	/*out, err := exec.Command(
		"lsblk", "--pairs", "--noheadings", "--output=name,mountpoint").Output()
	if err != nil {
		return nil, goof.WithError("error running lsblk", err)
	}

	input := string(out)

	// populate map parsing output from lsblk
	localDevices := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(bufio.ScanWords)

	count := 0
	var name string
	for scanner.Scan() {
		if count%2 == 0 {
			// get volume name
			name = "/dev/" + scanner.Text()[6:len(scanner.Text())-1]
		} else {
			// set mountpoint corresponding to volume name
			localDevices[name] = scanner.Text()[12 : len(scanner.Text())-1]
		}
		count++
	}*/

	return &types.LocalDevices{
		Driver:    ec2.Name,
		DeviceMap: localDevices,
	}, nil
}

func (d *driver) getEphemeralDevices() (deviceNames []string, err error) {
	// Get list of all block devices
	res, err := http.Get("http://169.254.169.254/latest/meta-data/block-device-mapping/")
	if err != nil {
		return nil, goof.WithError("ec2 block device mapping lookup failed", err)
	}
	blockDeviceMappings, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, goof.WithError("error reading ec2 block device mappings", err)
	}

	// Filter list of all block devices for ephemeral devices
	re, _ := regexp.Compile(`ephemeral([0-9]|1[0-9]|2[0-3])$`)

	scanner := bufio.NewScanner(strings.NewReader(string(blockDeviceMappings)))
	scanner.Split(bufio.ScanWords)

	var input string
	for scanner.Scan() {
		input = scanner.Text()
		if re.MatchString(input) {
			// Find device name for ephemeral device
			res, err := http.Get("http://169.254.169.254/latest/meta-data/block-device-mapping/" + input)
			if err != nil {
				return nil, goof.WithError("ec2 block device mapping lookup failed", err)
			}
			deviceName, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				return nil, goof.WithError("error reading ec2 block device mappings", err)
			}

			deviceNames = append(deviceNames, string(deviceName))
		}
	}

	return deviceNames, nil
}
