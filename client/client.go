package client

import (
	"fmt"

	"github.com/akutz/gofig"
	"github.com/akutz/gotil"

	apiclient "github.com/emccode/libstorage/api/client"
	"github.com/emccode/libstorage/api/types"
	apihttp "github.com/emccode/libstorage/api/types/http"
)

var (
	libstorHome = fmt.Sprintf("%s/.libstorage", gotil.HomeDir())
)

// Client is the libStorage client.
type Client interface {

	// Services returns a map of the configured Services.
	Services() (apihttp.ServicesMap, error)

	// ServiceInspect returns information about a service.
	ServiceInspect(name string) (*types.ServiceInfo, error)

	// Volumes returns all volumes for all configured services.
	Volumes(attachments bool) (apihttp.ServiceVolumeMap, error)

	// VolumeInspect gets information about a single volume.
	VolumeInspect(
		service, volumeID string, attachments bool) (*types.Volume, error)
}

type client struct {
	config gofig.Config
	apicli apiclient.Client
}

// New returns a new Client.
func New(config gofig.Config) (Client, error) {
	if config == nil {
		if cfg, err := getNewConfig(); err != nil {
			return nil, err
		} else {
			config = cfg
		}
	}
	apicli, err := apiclient.Dial(nil, config)
	if err != nil {
		return nil, err
	}
	return &client{config: config, apicli: apicli}, nil
}

func (c *client) Services() (apihttp.ServicesMap, error) {
	return c.apicli.Services()
}

func (c *client) ServiceInspect(service string) (*types.ServiceInfo, error) {
	return c.apicli.ServiceInspect(service)
}

func (c *client) Volumes(
	attachments bool) (apihttp.ServiceVolumeMap, error) {
	return c.apicli.Volumes()
}

func (c *client) VolumeInspect(
	service, volumeID string, attachments bool) (*types.Volume, error) {
	return c.apicli.VolumeInspect(service, volumeID, attachments)
}

func getNewConfig() (gofig.Config, error) {
	cfp := fmt.Sprintf("%s/config.yaml", libstorHome)
	if !gotil.FileExists(cfp) {
		cfp = fmt.Sprintf("%s/config.yml", libstorHome)
		if !gotil.FileExists(cfp) {
			return gofig.New(), nil
		}
	}
	config := gofig.New()
	if err := config.ReadConfigFile(cfp); err != nil {
		return nil, err
	}
	return config, nil
}