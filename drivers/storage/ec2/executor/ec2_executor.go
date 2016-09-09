package executor

import (
	"github.com/akutz/gofig"

	"github.com/emccode/libstorage/api/registry"
	"github.com/emccode/libstorage/api/types"
	"github.com/emccode/libstorage/drivers/storage/ebs"
	"github.com/emccode/libstorage/drivers/storage/ec2"
)

// driver is the storage executor for the ec2 storage driver.
type driver struct {
	config         gofig.Config
	nextDeviceInfo *types.NextDeviceInfo
	ebsx           types.StorageExecutor
}

func init() {
	registry.RegisterStorageExecutor(ec2.Name, newDriver)
}

func newDriver() types.StorageExecutor {
	return &driver{}
}

func (d *driver) Init(ctx types.Context, config gofig.Config) error {
	d.ebsx, _ = registry.NewStorageExecutor(ebs.Name)
	return d.ebsx.Init(ctx, config)
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
	return d.ebsx.InstanceID(ctx, opts)
}

// NextDevice returns the next available device.
func (d *driver) NextDevice(
	ctx types.Context,
	opts types.Store) (string, error) {
	return d.ebsx.NextDevice(ctx, opts)
}

func (d *driver) LocalDevices(
	ctx types.Context,
	opts *types.LocalDevicesOpts) (*types.LocalDevices, error) {
	return d.ebsx.LocalDevices(ctx, opts)
}
