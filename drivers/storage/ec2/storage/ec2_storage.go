package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/akutz/gofig"
	"github.com/akutz/goof"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	awsec2 "github.com/aws/aws-sdk-go/service/ec2"

	"github.com/emccode/libstorage/api/context"
	"github.com/emccode/libstorage/api/registry"
	"github.com/emccode/libstorage/api/types"
	"github.com/emccode/libstorage/drivers/storage/ec2"
)

// Config, client, and whatever else you need to connect to the provider
// Client varies with provider SDK
type driver struct {
	config           gofig.Config
	instanceDocument *instanceIdentityDocument
	ec2Instance      *awsec2.EC2
	ec2Tag           string
	awsCreds         *credentials.Credentials
}

type instanceIdentityDocument struct {
	InstanceID         string      `json:"instanceId"`
	BillingProducts    interface{} `json:"billingProducts"`
	AccountID          string      `json:"accountId"`
	ImageID            string      `json:"imageId"`
	InstanceType       string      `json:"instanceType"`
	KernelID           string      `json:"kernelId"`
	RamdiskID          string      `json:"ramdiskId"`
	PendingTime        string      `json:"pendingTime"`
	Architecture       string      `json:"architecture"`
	Region             string      `json:"region"`
	Version            string      `json:"version"`
	AvailabilityZone   string      `json:"availabilityZone"`
	DevpayproductCodes interface{} `json:"devpayProductCodes"`
	PrivateIP          string      `json:"privateIp"`
}

func init() {
	registry.RegisterStorageDriver(ec2.Name, newDriver)
}

func newDriver() types.StorageDriver {
	return &driver{}
}

func (d *driver) Name() string {
	return ec2.Name
}

// Init initializes the driver.
func (d *driver) Init(context types.Context, config gofig.Config) error {
	d.config = config

	// Initialize with config content
	fields := map[string]interface{}{
		"moduleName": d.Name(),
		//		"accessKey":  os.Getenv("AWS_ACCESS_KEY_ID"),
		"accessKey": d.accessKey(),
	}

	log.WithFields(fields).Debug("starting provider driver")

	// Mask password
	if d.secretKey() == "" {
		fields["secretKey"] = ""
	} else {
		fields["secretKey"] = "******"
	}

	var err error
	d.instanceDocument, err = getInstanceIdentityDocument()
	if err != nil {
		return goof.WithFieldsE(fields, "error getting instance id doc", err)
	}

	region := d.region()
	if region == "" {
		region = d.instanceDocument.Region
	}

	var endpoint string
	//endpoint := d.endpoint()
	if endpoint == "" {
		endpoint = "ec2.us-west-2.amazonaws.com"
	}

	d.ec2Tag = d.rexrayTag()

	mySession := session.New()

	d.awsCreds = credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.StaticProvider{Value: credentials.Value{AccessKeyID: d.accessKey(), SecretAccessKey: d.secretKey()}},
			//	&credentials.StaticProvider{Value: credentials.Value{AccessKeyID: os.Getenv("AWS_ACCESS_KEY_ID"), SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY")}},
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{},
			&ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(mySession),
			},
		})

	awsConfig := aws.NewConfig().WithCredentials(d.awsCreds).WithRegion(region).WithEndpoint(endpoint)

	d.ec2Instance = awsec2.New(mySession, awsConfig)

	log.WithFields(fields).Info("storage driver initialized")

	return nil
}

// NextDeviceInfo returns the information about the driver's next available
// device workflow.
// Not implemented yet
func (d *driver) NextDeviceInfo(
	ctx types.Context) (*types.NextDeviceInfo, error) {
	return nil, nil
}

// Type returns the type of storage the driver provides.
// Options: Block (block storage), NAS (network attached storage), Object (object-backed storage)
// See libstorage/api/types/types_model.go
func (d *driver) Type(ctx types.Context) (types.StorageType, error) {
	//Example: Block storage
	return types.Block, nil
}

// InstanceInspect returns an instance.
func (d *driver) InstanceInspect(
	ctx types.Context,
	opts types.Store) (*types.Instance, error) {
	// get instance ID
	iid := context.MustInstanceID(ctx)

	// If no instance ID, return blank instance
	if iid.ID != "" {
		return &types.Instance{InstanceID: iid}, nil
	}

	// Decode metadata from instance ID to get subnet ID
	var awsSubnetID string
	if err := iid.UnmarshalMetadata(&awsSubnetID); err != nil {
		return nil, err
	}
	instanceID := &types.InstanceID{ID: awsSubnetID, Driver: d.Name()}

	return &types.Instance{InstanceID: instanceID}, nil
}

// Volumes returns all volumes or a filtered list of volumes.
func (d *driver) Volumes(
	ctx types.Context,
	opts *types.VolumesOpts) ([]*types.Volume, error) {
	// Get all volumes (and their attachments if specified)
	vols, err := d.getVolume(ctx, "", "", opts.Attachments)
	if err != nil {
		return nil, err
	}
	return vols, nil
}

// VolumeInspect inspects a single volume.
func (d *driver) VolumeInspect(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeInspectOpts) (*types.Volume, error) {
	// Get volume corresponding to volume ID
	vols, err := d.getVolume(ctx, volumeID, "", opts.Attachments)
	if err != nil {
		return nil, err
	}
	if len(vols) == 0 {
		return nil, goof.New("no volumes returned")
	}

	// Because getVolume returns an array
	// and we only expect the 1st element to be a match, return 1st element
	return vols[0], nil
}

// VolumeCreate creates a new volume.
func (d *driver) VolumeCreate(ctx types.Context, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	return nil, types.ErrNotImplemented

	/*fields := map[string]interface{}{
		"volumeName": volumeName,
		"opts":       opts,
	}

	log.WithFields(fields).Debug("creating volume")

	// check if volume with same name exists
	volumes, err := d.getVolume(ctx, "", volumeName, false)
	if err != nil {
		return nil, err
	}

	if len(volumes) > 0 {
		return nil, goof.WithFields(goof.Fields{
			"moduleName": d.Name(),
			"driverName": d.Name(),
			"volumeName": volumeName}, "volume name already exists")
	}

	volume := &types.Volume{}

	// put parameters into new volume
	if opts.AvailabilityZone != nil {
		volume.AvailabilityZone = *opts.AvailabilityZone
	}
	if opts.Type != nil {
		volume.Type = *opts.Type
	}
	if opts.Size != nil {
		volume.Size = *opts.Size
	}
	if opts.IOPS != nil {
		volume.IOPS = *opts.IOPS
	}

	// pass in parameters to helper function to create the volume
	vol, err := d.createVolume(ctx, volumeName, volume)
	if err != nil {
		return nil, err
	}

	// return the volume created
	return d.VolumeInspect(ctx, *vol.VolumeId, &types.VolumeInspectOpts{
		Attachments: true,
	})*/
}

// VolumeCreateFromSnapshot creates a new volume from an existing snapshot.
// Not implemented yet
func (d *driver) VolumeCreateFromSnapshot(
	ctx types.Context,
	snapshotID, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	return nil, types.ErrNotImplemented
}

// VolumeCopy copies an existing volume.
// Not implemented yet
func (d *driver) VolumeCopy(
	ctx types.Context,
	volumeID, volumeName string,
	opts types.Store) (*types.Volume, error) {
	return nil, types.ErrNotImplemented
}

// VolumeSnapshot snapshots a volume.
// Not implemented yet
func (d *driver) VolumeSnapshot(
	ctx types.Context,
	volumeID, snapshotName string,
	opts types.Store) (*types.Snapshot, error) {
	return nil, types.ErrNotImplemented
}

// VolumeRemove removes a volume.
func (d *driver) VolumeRemove(
	ctx types.Context,
	volumeID string,
	opts types.Store) error {
	return types.ErrNotImplemented

	/*fields := map[string]interface{}{
		"provider": ec2.Name,
		"volumeID": volumeID,
	}

	// no volume ID inputted
	if volumeID == "" {
		return goof.New("missing volume id")
	}

	dvInput := &awsec2.DeleteVolumeInput{
		VolumeId: &volumeID,
	}
	_, err := d.ec2Instance.DeleteVolume(dvInput)
	if err != nil {
		return goof.WithFieldsE(fields, "error deleting volume", err)
	}

	return nil*/
}

// VolumeAttach attaches a volume and provides a token clients can use
// to validate that device has appeared locally.
func (d *driver) VolumeAttach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeAttachOpts) (*types.Volume, string, error) {
	return nil, "", types.ErrNotImplemented
	// 	// no volume ID inputted
	// 	if volumeID == "" {
	// 		return nil, "", goof.New("missing volume id")
	// 	}
	// 	/*
	// 		nextDeviceName, err := d.GetDeviceNextAvailable()
	// 		if err != nil {
	// 			return nil, err
	// 		}*/

	// 	// review volume with attachments to any host
	// 	volumes, err := d.getVolume(ctx, volumeID, "", false)
	// 	if err != nil {
	// 		return nil, "", err
	// 	}

	// 	// sanity checks: is there a volume to attach? is volume already attached?
	// 	if len(volumes) == 0 {
	// 		return nil, "", goof.New("no volume found")
	// 	}
	// 	if len(volumes[0].Attachments) > 0 && !opts.Force {
	// 		return nil, "", goof.New("volume already attached to a host")
	// 	}
	// 	// option to force attachment - detach other volume first
	// 	if opts.Force {
	// 		if _, err := d.VolumeDetach(ctx, volumeID, nil); err != nil {
	// 			return nil, "", err
	// 		}
	// 	}

	// 	// call helper function
	// 	err = d.attachVolume(ctx, volumeID, "")
	// 	if err != nil {
	// 		return nil, "", goof.WithFieldsE(
	// 			log.Fields{
	// 				"provider": ec2.Name,
	// 				"volumeID": volumeID},
	// 			"error attaching volume",
	// 			err,
	// 		)
	// 	}

	// 	// check if successful attach
	// 	attachedVol, err := d.VolumeInspect(
	// 		ctx, volumeID, &types.VolumeInspectOpts{
	// 			Attachments: true,
	// 			Opts:        opts.Opts,
	// 		})
	// 	if err != nil {
	// 		return nil, "", goof.WithError("error getting volume", err)
	// 	}

	// 	return attachedVol, attachedVol.ID, nil
}

// VolumeDetach detaches a volume.
func (d *driver) VolumeDetach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeDetachOpts) (*types.Volume, error) {
	return nil, types.ErrNotImplemented
	// 	// check for errors:
	// 	// no volume ID inputted
	// 	if volumeID == "" {
	// 		return nil, goof.New("missing volume id")
	// 	}

	// 	volumes, err := d.getVolume(ctx, volumeID, "", false)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	// no volumes to detach
	// 	if len(volumes) == 0 {
	// 		return nil, goof.New("no volume returned")
	// 	}

	// 	// volume has no attachments
	// 	if len(volumes[0].Attachments) == 0 {
	// 		return nil, goof.New("volume already detached")
	// 	}

	// 	// TODO put into helper function i.e. detachVolume?
	// 	dvInput := &awsec2.DetachVolumeInput{
	// 		VolumeId: &volumeID,
	// 		Force:    &opts.Force,
	// 	}

	// 	if _, err = d.ec2Instance.DetachVolume(dvInput); err != nil {
	// 		return nil, goof.WithFieldsE(
	// 			log.Fields{
	// 				"provider": ec2.Name,
	// 				"volumeID": volumeID}, "error detaching volume", err)
	// 	}

	// 	ctx.Info("detached volume", volumeID)

	// 	return d.VolumeInspect(
	// 		ctx, volumeID, &types.VolumeInspectOpts{Attachments: true})
}

// Snapshots returns all volumes or a filtered list of snapshots.
// Not implemented
func (d *driver) Snapshots(
	ctx types.Context,
	opts types.Store) ([]*types.Snapshot, error) {
	return nil, nil
}

// SnapshotInspect inspects a single snapshot.
// Not implemented
func (d *driver) SnapshotInspect(
	ctx types.Context,
	snapshotID string,
	opts types.Store) (*types.Snapshot, error) {
	return nil, nil
}

// SnapshotCopy copies an existing snapshot.
// Not implemented
func (d *driver) SnapshotCopy(
	ctx types.Context,
	snapshotID, snapshotName, destinationID string,
	opts types.Store) (*types.Snapshot, error) {
	return nil, nil
}

// SnapshotRemove removes a snapshot.
// Not implemented
func (d *driver) SnapshotRemove(
	ctx types.Context,
	snapshotID string,
	opts types.Store) error {
	return nil
}

///////////////////////////////////////////////////////////////////////
/////////        HELPER FUNCTIONS SPECIFIC TO PROVIDER        /////////
///////////////////////////////////////////////////////////////////////
// getVolume searches and returns a volume matching criteria
func (d *driver) getVolume(
	ctx types.Context,
	volumeID string, volumeName string,
	attachments bool) ([]*types.Volume, error) {
	filters := []*awsec2.Filter{}
	if volumeName != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("tag:Name"), Values: []*string{&volumeName}})
	}

	if volumeID != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("volume-id"), Values: []*string{&volumeID}})
	}

	if d.ec2Tag != "" {
		filters = append(filters, &awsec2.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", d.rexrayTag())),
			Values: []*string{&d.ec2Tag}})
	}

	// Prepare input
	dvInput := &awsec2.DescribeVolumesInput{}

	// Apply filters if parameters are specified
	if len(filters) > 0 {
		dvInput.Filters = filters
	}

	if volumeID != "" {
		dvInput.VolumeIds = []*string{&volumeID}
	}

	resp, err := d.ec2Instance.DescribeVolumes(dvInput)
	if err != nil {
		return []*types.Volume{}, err
	}

	// TODO update fields?
	volumes := resp.Volumes

	var volumesSD []*types.Volume
	for _, volume := range volumes {
		var attachmentsSD []*types.VolumeAttachment
		name := getName(volume.Tags)

		volumeSD := &types.Volume{
			Name:             name,
			ID:               *volume.VolumeId,
			AvailabilityZone: *volume.AvailabilityZone,
			Status:           *volume.State,
			Type:             *volume.VolumeType,
			Size:             *volume.Size,
		}
		if attachments {
			for _, attachment := range volume.Attachments {
				attachmentSD := &types.VolumeAttachment{
					VolumeID:   *attachment.VolumeId,
					InstanceID: &types.InstanceID{ID: *attachment.InstanceId, Driver: ec2.Name},
					DeviceName: *attachment.Device,
					Status:     *attachment.State,
				}
				attachmentsSD = append(attachmentsSD, attachmentSD)
			}

			if len(attachmentsSD) > 0 {
				volumeSD.Attachments = attachmentsSD
			}
		}
		// Some volume types have no IOPS, so we get nil in volume.Iops
		if volume.Iops != nil {
			volumeSD.IOPS = *volume.Iops
		}
		volumesSD = append(volumesSD, volumeSD)
	}
	return volumesSD, nil
}

// Used in VolumeAttach
func (d *driver) attachVolume(
	ctx types.Context, volumeID, volumeName string) error {
	return types.ErrNotImplemented
	/* TODO sanity check # of volumes to attach?
	medium, err := d.vbox.GetMedium(volumeID, volumeName)
	if err != nil {
		return err
	}

	if len(medium) == 0 {
		return goof.New("no volume returned")
	}
	if len(medium) > 1 {
		return goof.New("too many volumes returned")
	}
	*/

	// avInput := &awsec2.AttachVolumeInput{
	// 	InstanceId: &d.instanceDocument.InstanceID,
	// 	VolumeId:   &volumeID,
	// }
	// if _, err := d.ec2Instance.AttachVolume(avInput); err != nil {
	// 	return err
	// }
	// return nil
}

func getInstanceIdentityDocument() (*instanceIdentityDocument, error) {
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 50*time.Millisecond)
	if err != nil {
		return &instanceIdentityDocument{}, fmt.Errorf("Error: %v\n", err)
	}
	defer conn.Close()

	url := "http://169.254.169.254/latest/dynamic/instance-identity/document"
	resp, err := http.Get(url)
	if err != nil {
		return &instanceIdentityDocument{}, fmt.Errorf("Error: %v\n", err)
	}

	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return &instanceIdentityDocument{}, fmt.Errorf("Error: %v\n", err)
	}

	var document instanceIdentityDocument
	err = json.Unmarshal(data, &document)
	if err != nil {
		return &instanceIdentityDocument{}, fmt.Errorf("Error: %v\n", err)
	}

	return &document, nil
}

func (d *driver) createVolume(ctx types.Context, volumeName string,
	vol *types.Volume) (*awsec2.Volume, error) {
	return nil, types.ErrNotImplemented
	// var err error

	// var server awsec2.Instance
	// if server, err = d.getInstance(); err != nil {
	// 	return &awsec2.Volume{}, err
	// }

	// d.createVolumeEnsureAvailabilityZone(&vol.AvailabilityZone, &server)

	// options := &awsec2.CreateVolumeInput{
	// 	Size:             &vol.Size,
	// 	AvailabilityZone: &vol.AvailabilityZone,
	// 	VolumeType:       &vol.Type,
	// }

	// if vol.IOPS > 0 {
	// 	options.Iops = &vol.IOPS
	// }

	// var resp *awsec2.Volume
	// if resp, err = d.ec2Instance.CreateVolume(options); err != nil {
	// 	return &awsec2.Volume{}, err
	// }

	// if err = d.createVolumeCreateTags(volumeName, resp); err != nil {
	// 	return &awsec2.Volume{}, err
	// }

	// if err = d.waitVolumeComplete(resp); err != nil {
	// 	return &awsec2.Volume{}, err
	// }

	// return resp, nil
}

func (d *driver) createVolumeEnsureAvailabilityZone(
	availabilityZone *string, server *awsec2.Instance) {
	// if *availabilityZone == "" {
	// 	*availabilityZone = *server.Placement.AvailabilityZone
	// }
}

func (d *driver) createVolumeCreateTags(
	volumeName string, resp *awsec2.Volume) (err error) {
	return types.ErrNotImplemented
	// if volumeName == "" && d.ec2Tag == "" {
	// 	return
	// }

	// var ctInput *awsec2.CreateTagsInput
	// initCTInput := func() {
	// 	if ctInput != nil {
	// 		return
	// 	}
	// 	ctInput = &awsec2.CreateTagsInput{
	// 		Resources: []*string{resp.VolumeId},
	// 		Tags:      []*awsec2.Tag{},
	// 	}
	// }

	// if volumeName != "" {
	// 	initCTInput()
	// 	ctInput.Tags = append(
	// 		ctInput.Tags,
	// 		&awsec2.Tag{
	// 			Key:   aws.String("Name"),
	// 			Value: &volumeName,
	// 		})
	// }

	// if d.ec2Tag != "" {
	// 	initCTInput()
	// 	ctInput.Tags = append(
	// 		ctInput.Tags,
	// 		&awsec2.Tag{
	// 			Key:   aws.String(d.rexrayTag()),
	// 			Value: &d.ec2Tag,
	// 		})
	// }

	// _, err = d.ec2Instance.CreateTags(ctInput)
	// if err != nil {
	// 	return err
	// }
	// return nil
}

func (d *driver) waitVolumeComplete(resp *awsec2.Volume) error {
	return types.ErrNotImplemented
	// for {
	// 	if *resp.State == awsec2.VolumeStateAvailable {
	// 		break
	// 	}
	// 	time.Sleep(1 * time.Second)
	// }

	// return nil
}

func getName(tags []*awsec2.Tag) string {
	for _, tag := range tags {
		if *tag.Key == "Name" {
			return *tag.Value
		}
	}
	return ""
}

func (d *driver) getInstance() (awsec2.Instance, error) {
	return awsec2.Instance{}, types.ErrNotImplemented

	// diInput := &awsec2.DescribeInstancesInput{
	// 	InstanceIds: []*string{&d.instanceDocument.InstanceID},
	// }
	// resp, err := d.ec2Instance.DescribeInstances(diInput)
	// if err != nil {
	// 	return awsec2.Instance{}, err
	// }

	// return *resp.Reservations[0].Instances[0], nil
}

func (d *driver) accessKey() string {
	return d.config.GetString("ec2.accessKey")
}

func (d *driver) secretKey() string {
	return d.config.GetString("ec2.secretKey")
}

func (d *driver) region() string {
	return d.config.GetString("ec2.region")
}

func (d *driver) rexrayTag() string {
	return d.config.GetString("ec2.rexrayTag")
}
