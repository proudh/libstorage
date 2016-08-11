package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
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

const (
	//@enum WaitAction
	WaitVolumeCreate = "create"
	//@enum WaitAction
	WaitVolumeAttach = "attach"
	//@enum WaitAction
	WaitVolumeDetach = "detach"
)

// Config, client, and whatever else you need to connect to the provider
// Client varies with provider SDK
type driver struct {
	config           gofig.Config
	nextDeviceInfo   *types.NextDeviceInfo
	instanceDocument *instanceIdentityDocument
	ec2Instance      *awsec2.EC2
	//	ec2Tag           string
	awsCreds *credentials.Credentials
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

	d.nextDeviceInfo = &types.NextDeviceInfo{
		Prefix:  "xvd",
		Pattern: "[a-z]",
		Ignore:  false,
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

	endpoint := d.endpoint()
	if endpoint == "" {
		endpoint = fmt.Sprintf("ec2.%s.amazonaws.com", region)
	}

	//	d.ec2Tag = d.rexrayTag()

	mySession := session.New()

	d.awsCreds = credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.StaticProvider{Value: credentials.Value{AccessKeyID: d.accessKey(), SecretAccessKey: d.secretKey()}},
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
func (d *driver) NextDeviceInfo(
	ctx types.Context) (*types.NextDeviceInfo, error) {
	return d.nextDeviceInfo, nil
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
	ec2vols, err := d.getVolume(ctx, "", "")
	if err != nil {
		return nil, err
	}
	if len(ec2vols) == 0 {
		return nil, goof.New("no volumes returned")
	}
	vols := d.toTypesVolume(ec2vols, opts.Attachments)
	return vols, nil
}

// VolumeInspect inspects a single volume.
func (d *driver) VolumeInspect(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeInspectOpts) (*types.Volume, error) {
	// Get volume corresponding to volume ID
	ec2vols, err := d.getVolume(ctx, volumeID, "")
	if err != nil {
		return nil, err
	}
	if len(ec2vols) == 0 {
		return nil, goof.New("no volumes returned")
	}
	vols := d.toTypesVolume(ec2vols, opts.Attachments)

	// Because getVolume returns an array
	// and we only expect the 1st element to be a match, return 1st element
	return vols[0], nil
}

// VolumeCreate creates a new volume.
func (d *driver) VolumeCreate(ctx types.Context, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	fields := map[string]interface{}{
		"volumeName": volumeName,
		"opts":       opts,
	}

	log.WithFields(fields).Debug("creating volume")

	// check if volume with same name exists
	ec2vols, err := d.getVolume(ctx, "", volumeName)
	volumes := d.toTypesVolume(ec2vols, false)
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
	vol, err := d.createVolume(ctx, volumeName, "", volume)
	if err != nil {
		return nil, err
	}
	// return the volume created
	return d.VolumeInspect(ctx, *vol.VolumeId, &types.VolumeInspectOpts{
		Attachments: true,
	})
}

// VolumeCreateFromSnapshot creates a new volume from an existing snapshot.
func (d *driver) VolumeCreateFromSnapshot(
	ctx types.Context,
	snapshotID, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	fields := map[string]interface{}{
		"snapshotID": snapshotID,
		"volumeName": volumeName,
		"opts":       opts,
	}

	log.WithFields(fields).Debug("creating volume from snapshot")

	// check if volume with same name exists
	ec2vols, err := d.getVolume(ctx, "", volumeName)
	volumes := d.toTypesVolume(ec2vols, false)
	if err != nil {
		return &types.Volume{}, goof.WithError(
			"error getting volume", err)
	}

	if len(volumes) > 0 {
		return nil, goof.WithFields(goof.Fields{
			"moduleName": d.Name(),
			"driverName": d.Name(),
			"snapshotID": snapshotID,
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
	vol, err := d.createVolume(ctx, volumeName, snapshotID, volume)
	if err != nil {
		return &types.Volume{}, goof.WithError(
			"error creating volume", err)
	}
	// return the volume created
	return d.VolumeInspect(ctx, *vol.VolumeId, &types.VolumeInspectOpts{
		Attachments: true,
	})
}

// VolumeCopy copies an existing volume.
func (d *driver) VolumeCopy(
	ctx types.Context,
	volumeID, volumeName string,
	opts types.Store) (*types.Volume, error) {
	var (
		ec2vols  []*awsec2.Volume
		err      error
		snapshot *types.Snapshot
		vol      *types.Volume
	)

	if volumeID == "" {
		return &types.Volume{}, goof.New("missing volume id")
	}

	fields := map[string]interface{}{
		"volumeID":   volumeID,
		"volumeName": volumeName,
		"opts":       opts,
	}

	log.WithFields(fields).Debug("creating volume from snapshot")

	// check if volume with same name exists
	ec2VolsToCheck, err := d.getVolume(ctx, "", volumeName)
	volsToCheck := d.toTypesVolume(ec2VolsToCheck, false)
	if err != nil {
		return &types.Volume{}, goof.WithError(
			"error getting volume", err)
	}

	if len(volsToCheck) > 0 {
		return nil, goof.WithFields(goof.Fields{
			"moduleName": d.Name(),
			"driverName": d.Name(),
			"volumeName": volumeName}, "volume name already exists")
	}

	// get volume using volumeID and/or volumeName
	ec2vols, err = d.getVolume(ctx, volumeID, "")
	if err != nil {
		return &types.Volume{}, goof.WithError(
			"error getting volume", err)
	}
	volumes := d.toTypesVolume(ec2vols, false)
	if len(volumes) > 1 {
		return &types.Volume{},
			goof.New("multiple volumes returned")
	} else if len(volumes) == 0 {
		return &types.Volume{}, goof.New("no volumes returned")
	}

	// create snapshot from volumeID
	snapshotName := fmt.Sprintf("temp-snap-%s", volumeID)
	snapshot, err = d.VolumeSnapshot(ctx, volumeID, snapshotName, opts)
	if err != nil {
		return &types.Volume{}, goof.WithError(
			"error creating temporary snapshot", err)
	}

	// use temporary snapshot to create volume
	vol, err = d.VolumeCreateFromSnapshot(ctx, snapshot.ID,
		volumeName, &types.VolumeCreateOpts{Opts: opts})
	if err != nil {
		return &types.Volume{}, goof.WithError(
			"error creating volume copy from snapshot", err)
	}

	// remove temp snapshot created
	if err = d.SnapshotRemove(ctx, snapshot.ID, opts); err != nil {
		return &types.Volume{}, goof.WithError(
			"error removing temporary snapshot", err)
	}

	log.Println("Created volume " + vol.ID + " from volume " + volumeID)
	return vol, nil
}

// VolumeSnapshot snapshots a volume.
func (d *driver) VolumeSnapshot(
	ctx types.Context,
	volumeID, snapshotName string,
	opts types.Store) (*types.Snapshot, error) {

	// no volume ID inputted
	if volumeID == "" {
		return nil, goof.New("missing volume id")
	}

	csInput := &awsec2.CreateSnapshotInput{
		VolumeId: &volumeID,
	}

	resp, err := d.ec2Instance.CreateSnapshot(csInput)
	if err != nil {
		return nil, err
	}

	if err = d.createTags(*resp.SnapshotId, snapshotName); err != nil {
		return &types.Snapshot{}, goof.WithError(
			"Error creating tags", err)
	}

	log.Println("Waiting for snapshot to complete")
	err = d.waitSnapshotComplete(ctx, *resp.SnapshotId)
	if err != nil {
		return &types.Snapshot{}, goof.WithError(
			"Error waiting for snapshot creation", err)
	}

	snapshot, err := d.SnapshotInspect(ctx, *resp.SnapshotId, nil)
	if err != nil {
		return &types.Snapshot{}, goof.WithError(
			"Error getting snapshot", err)
	}

	log.Println("Created Snapshot: " + snapshot.ID)
	return snapshot, nil
}

// VolumeRemove removes a volume.
func (d *driver) VolumeRemove(
	ctx types.Context,
	volumeID string,
	opts types.Store) error {
	fields := map[string]interface{}{
		"provider": ec2.Name,
		"volumeID": volumeID,
	}

	// no volume ID inputted
	if volumeID == "" {
		return goof.New("missing volume id")
	}

	//TODO check if volume is attached? if so fail

	dvInput := &awsec2.DeleteVolumeInput{
		VolumeId: &volumeID,
	}
	_, err := d.ec2Instance.DeleteVolume(dvInput)
	if err != nil {
		return goof.WithFieldsE(fields, "error deleting volume", err)
	}

	return nil
}

// VolumeAttach attaches a volume and provides a token clients can use
// to validate that device has appeared locally.
func (d *driver) VolumeAttach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeAttachOpts) (*types.Volume, string, error) {
	// no volume ID inputted
	if volumeID == "" {
		return nil, "", goof.New("missing volume id")
	}
	nextDeviceName, err := d.GetNextAvailableDeviceName()
	if err != nil {
		return nil, "", err
	}

	// review volume with attachments to any host
	ec2vols, err := d.getVolume(ctx, volumeID, "")
	volumes := d.toTypesVolume(ec2vols, true)
	if err != nil {
		return nil, "", goof.WithError("Error getting volume", err)
	}

	// sanity checks: is there a volume to attach? is volume already attached?
	if len(volumes) == 0 {
		return nil, "", goof.New("no volume found")
	}
	if len(volumes[0].Attachments) > 0 && !opts.Force {
		return nil, "", goof.New("volume already attached to a host")
	}
	if opts.Force {
		if _, err := d.VolumeDetach(ctx, volumeID, nil); err != nil {
			return nil, "", err
		}
	}

	// call helper function
	err = d.attachVolume(ctx, volumeID, volumes[0].Name, nextDeviceName)
	if err != nil {
		return nil, "", goof.WithFieldsE(
			log.Fields{
				"provider": ec2.Name,
				"volumeID": volumeID},
			"error attaching volume",
			err,
		)
	}

	if err = d.waitVolumeComplete(ctx, volumeID, WaitVolumeAttach); err != nil {
		return nil, "", goof.WithError("error waiting for volume attach", err)
	}

	// check if successful attach
	attachedVol, err := d.VolumeInspect(
		ctx, volumeID, &types.VolumeInspectOpts{
			Attachments: true,
			Opts:        opts.Opts,
		})
	if err != nil {
		return nil, "", goof.WithError("error getting volume", err)
	}

	return attachedVol, attachedVol.ID, nil
}

// VolumeDetach detaches a volume.
func (d *driver) VolumeDetach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeDetachOpts) (*types.Volume, error) {
	// check for errors:
	// no volume ID inputted
	if volumeID == "" {
		return nil, goof.New("missing volume id")
	}

	ec2vols, err := d.getVolume(ctx, volumeID, "")
	volumes := d.toTypesVolume(ec2vols, true)

	if err != nil {
		return nil, err
	}

	// no volumes to detach
	if len(volumes) == 0 {
		return nil, goof.New("no volume returned")
	}

	// volume has no attachments
	if len(volumes[0].Attachments) == 0 {
		return nil, goof.New("volume already detached")
	}

	dvInput := &awsec2.DetachVolumeInput{
		VolumeId: &volumeID,
		Force:    &opts.Force,
	}

	if _, err = d.ec2Instance.DetachVolume(dvInput); err != nil {
		return nil, goof.WithFieldsE(
			log.Fields{
				"provider": ec2.Name,
				"volumeID": volumeID}, "error detaching volume", err)
	}

	if err = d.waitVolumeComplete(ctx, volumeID, WaitVolumeDetach); err != nil {
		return nil, goof.WithError("error waiting for volume detach", err)
	}

	ctx.Info("detached volume", volumeID)

	// check if successful detach
	detachedVol, err := d.VolumeInspect(
		ctx, volumeID, &types.VolumeInspectOpts{
			Attachments: true,
			Opts:        opts.Opts,
		})
	if err != nil {
		return nil, goof.WithError("error getting volume", err)
	}

	return detachedVol, nil
}

// Snapshots returns all volumes or a filtered list of snapshots.
func (d *driver) Snapshots(
	ctx types.Context,
	opts types.Store) ([]*types.Snapshot, error) {
	// Get all snapshots
	ec2snapshots, err := d.getSnapshot(ctx, "", "", "")
	if err != nil {
		return nil, err
	}
	if len(ec2snapshots) == 0 {
		return nil, goof.New("no snapshots returned")
	}
	snapshots := d.toTypesSnapshot(ec2snapshots)
	return snapshots, nil
}

// SnapshotInspect inspects a single snapshot.
func (d *driver) SnapshotInspect(
	ctx types.Context,
	snapshotID string,
	opts types.Store) (*types.Snapshot, error) {
	// Get snapshot corresponding to snapshot ID
	ec2snapshots, err := d.getSnapshot(ctx, "", snapshotID, "")
	if err != nil {
		return nil, err
	}
	if len(ec2snapshots) == 0 {
		return nil, goof.New("no snapshots returned")
	}
	snapshots := d.toTypesSnapshot(ec2snapshots)

	// Because getSnapshot returns an array
	// and we only expect the 1st element to be a match, return 1st element
	return snapshots[0], nil
}

// SnapshotCopy copies an existing snapshot.
func (d *driver) SnapshotCopy(
	ctx types.Context,
	snapshotID, snapshotName, destinationID string,
	opts types.Store) (*types.Snapshot, error) {
	if snapshotID == "" {
		return &types.Snapshot{}, goof.New("Missing snapshotID")
	}

	origSnapshots, err := d.getSnapshot(ctx, "", snapshotID, "")
	if err != nil {
		return &types.Snapshot{},
			goof.WithError("Error getting snapshot", err)
	}

	if len(origSnapshots) > 1 {
		return &types.Snapshot{},
			goof.New("multiple snapshots returned")
	} else if len(origSnapshots) == 0 {
		return &types.Snapshot{}, goof.New("no snapshots returned")
	}

	snapshotID = *(origSnapshots[0]).SnapshotId
	snapshotName = d.getName(origSnapshots[0].Tags)

	options := &awsec2.CopySnapshotInput{
		SourceSnapshotId: &snapshotID,
		SourceRegion:     &d.instanceDocument.Region,
		Description:      aws.String(fmt.Sprintf("Copy of %s", snapshotID)),
	}
	resp := &awsec2.CopySnapshotOutput{}

	resp, err = d.ec2Instance.CopySnapshot(options)
	if err != nil {
		return nil, err
	}

	if err = d.createTags(*resp.SnapshotId, snapshotName); err != nil {
		return &types.Snapshot{}, goof.WithError(
			"Error creating tags", err)
	}

	log.WithFields(log.Fields{
		"moduleName":      d.Name(),
		"driverName":      d.Name(),
		"snapshotName":    snapshotName,
		"resp.SnapshotId": *resp.SnapshotId}).Info("waiting for snapshot to complete")

	err = d.waitSnapshotComplete(ctx, *resp.SnapshotId)
	if err != nil {
		return &types.Snapshot{}, goof.WithError(
			"Error waiting for snapshot creation", err)
	}

	snapshotCopy, err := d.SnapshotInspect(ctx, *resp.SnapshotId, nil)
	if err != nil {
		return &types.Snapshot{}, goof.WithError(
			"Error getting snapshot copy", err)
	}
	destinationID = snapshotCopy.ID

	log.Println("Copied Snapshot: " + destinationID)
	return snapshotCopy, nil
}

// SnapshotRemove removes a snapshot.
func (d *driver) SnapshotRemove(
	ctx types.Context,
	snapshotID string,
	opts types.Store) error {
	fields := map[string]interface{}{
		"provider":   ec2.Name,
		"snapshotID": snapshotID,
	}

	// no snapshot ID inputted
	if snapshotID == "" {
		return goof.New("missing snapshot id")
	}

	dsInput := &awsec2.DeleteSnapshotInput{
		SnapshotId: &snapshotID,
	}
	_, err := d.ec2Instance.DeleteSnapshot(dsInput)
	if err != nil {
		return goof.WithFieldsE(fields, "error deleting snapshot", err)
	}

	return nil
}

///////////////////////////////////////////////////////////////////////
/////////        HELPER FUNCTIONS SPECIFIC TO PROVIDER        /////////
///////////////////////////////////////////////////////////////////////
// getVolume searches and returns a volume matching criteria
func (d *driver) getVolume(
	ctx types.Context,
	volumeID string, volumeName string) ([]*awsec2.Volume, error) {
	filters := []*awsec2.Filter{}
	if volumeName != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("tag:Name"), Values: []*string{&volumeName}})
	}

	if volumeID != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("volume-id"), Values: []*string{&volumeID}})
	}

	/*	if d.ec2Tag != "" {
			filters = append(filters, &awsec2.Filter{
				Name:   aws.String(fmt.Sprintf("tag:%s", d.rexrayTag())),
				Values: []*string{&d.ec2Tag}})
		}
	*/
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
		return []*awsec2.Volume{}, err
	}

	return resp.Volumes, nil
}

func (d *driver) toTypesVolume(
	ec2vols []*awsec2.Volume, attachments bool) []*types.Volume {
	var volumesSD []*types.Volume
	for _, volume := range ec2vols {
		var attachmentsSD []*types.VolumeAttachment
		name := d.getName(volume.Tags)

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
	return volumesSD
}

func (d *driver) getSnapshot(
	ctx types.Context,
	volumeID, snapshotID, snapshotName string) ([]*awsec2.Snapshot, error) {
	filters := []*awsec2.Filter{}
	if snapshotName != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("tag:Name"), Values: []*string{&snapshotName}})
	}

	if volumeID != "" {
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("volume-id"), Values: []*string{&volumeID}})
	}

	if snapshotID != "" {
		//using SnapshotIds in request is returning stale data
		filters = append(filters, &awsec2.Filter{
			Name: aws.String("snapshot-id"), Values: []*string{&snapshotID}})
	}

	/*	if d.ec2Tag != "" {
		filters = append(filters, &ec2.Filter{
			Name:   aws.String(fmt.Sprintf("tag:%s", rexrayTag)),
			Values: []*string{&d.ec2Tag}})
	}*/

	dsInput := &awsec2.DescribeSnapshotsInput{}

	if len(filters) > 0 {
		dsInput.Filters = filters
	}

	resp, err := d.ec2Instance.DescribeSnapshots(dsInput)
	if err != nil {
		return nil, err
	}

	return resp.Snapshots, nil
}

func (d *driver) toTypesSnapshot(
	ec2snapshots []*awsec2.Snapshot) []*types.Snapshot {
	var snapshotsInt []*types.Snapshot
	for _, snapshot := range ec2snapshots {
		name := d.getName(snapshot.Tags)
		snapshotSD := &types.Snapshot{
			Name:        name,
			VolumeID:    *snapshot.VolumeId,
			ID:          *snapshot.SnapshotId,
			VolumeSize:  *snapshot.VolumeSize,
			StartTime:   (*snapshot.StartTime).Unix(),
			Description: *snapshot.Description,
			Status:      *snapshot.State,
		}
		snapshotsInt = append(snapshotsInt, snapshotSD)
	}

	// log.Println("Got Snapshots: " + fmt.Sprintf("%+v", snapshotsInt))
	return snapshotsInt
}

// Used in VolumeAttach
func (d *driver) attachVolume(
	ctx types.Context, volumeID, volumeName, deviceName string) error {
	// sanity check # of volumes to attach
	vol, err := d.getVolume(ctx, volumeID, volumeName)
	if err != nil {
		return goof.WithError("Error getting volume", err)
	}

	if len(vol) == 0 {
		return goof.New("no volume returned")
	}
	if len(vol) > 1 {
		return goof.New("too many volumes returned")
	}

	avInput := &awsec2.AttachVolumeInput{
		Device:     &deviceName,
		InstanceId: &d.instanceDocument.InstanceID,
		VolumeId:   &volumeID,
	}
	if _, err := d.ec2Instance.AttachVolume(avInput); err != nil {
		return err
	}
	return nil
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

func (d *driver) GetNextAvailableDeviceName() (string, error) {
	letters := []string{
		"a", "b", "c", "d", "e", "f", "g", "h",
		"i", "j", "k", "l", "m", "n", "o", "p"}

	blockDeviceNames := make(map[string]bool)

	blockDeviceMapping, err := d.GetVolumeMapping()
	if err != nil {
		return "", err
	}

	for _, blockDevice := range blockDeviceMapping {
		re, _ := regexp.Compile(`^/dev/` +
			d.nextDeviceInfo.Prefix +
			`(` + d.nextDeviceInfo.Pattern + `)`)
		res := re.FindStringSubmatch(blockDevice.Name)
		if len(res) > 0 {
			blockDeviceNames[res[1]] = true
		}
	}

	localDevices, err := getLocalDevices()
	if err != nil {
		return "", err
	}

	for _, localDevice := range localDevices {
		re, _ := regexp.Compile(`^` +
			d.nextDeviceInfo.Prefix +
			`(` + d.nextDeviceInfo.Pattern + `)`)
		res := re.FindStringSubmatch(localDevice)
		if len(res) > 0 {
			blockDeviceNames[res[1]] = true
		}
	}

	for _, letter := range letters {
		if !blockDeviceNames[letter] {
			nextDeviceName := "/dev/" +
				d.nextDeviceInfo.Prefix + letter
			log.WithFields(log.Fields{
				"driverName":     d.Name(),
				"nextDeviceName": nextDeviceName}).Info("got next device name")
			return nextDeviceName, nil
		}
	}
	return "", goof.New("No available device")
}

func getLocalDevices() (deviceNames []string, err error) {
	file := "/proc/partitions"
	contentBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return []string{}, err
	}

	content := string(contentBytes)

	lines := strings.Split(content, "\n")
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		if len(fields) == 4 {
			deviceNames = append(deviceNames, fields[3])
		}
	}

	return deviceNames, nil
}

func (d *driver) GetVolumeMapping() ([]*types.VolumeDevice, error) {
	blockDevices, err := d.getBlockDevices(d.instanceDocument.InstanceID)
	if err != nil {
		return nil, goof.WithError("Error getting block devices", err)
	}

	var BlockDevices []*types.VolumeDevice
	for _, blockDevice := range blockDevices {
		sdBlockDevice := &types.VolumeDevice{
			ProviderName: d.Name(),
			InstanceID:   &types.InstanceID{ID: d.instanceDocument.InstanceID, Driver: ec2.Name},
			//InstanceID:   d.instanceDocument.InstanceID,
			Region:   d.instanceDocument.Region,
			Name:     *blockDevice.DeviceName,
			VolumeID: *((*blockDevice.Ebs).VolumeId),
			Status:   *((*blockDevice.Ebs).Status),
		}
		BlockDevices = append(BlockDevices, sdBlockDevice)
	}

	// log.Println("Got Block Device Mappings: " + fmt.Sprintf("%+v", BlockDevices))
	return BlockDevices, nil
}

func (d *driver) getBlockDevices(
	instanceID string) ([]*awsec2.InstanceBlockDeviceMapping, error) {

	instance, err := d.getInstance()
	if err != nil {
		return nil, goof.WithError("Error getting instance", err)
	}

	return instance.BlockDeviceMappings, nil
}

func (d *driver) createVolume(ctx types.Context, volumeName, snapshotID string,
	vol *types.Volume) (*awsec2.Volume, error) {
	var err error

	var server awsec2.Instance
	if server, err = d.getInstance(); err != nil {
		return &awsec2.Volume{}, err
	}

	d.createVolumeEnsureAvailabilityZone(&vol.AvailabilityZone, &server)

	options := &awsec2.CreateVolumeInput{
		Size:             &vol.Size,
		AvailabilityZone: &vol.AvailabilityZone,
		VolumeType:       &vol.Type,
	}
	if snapshotID != "" {
		options.SnapshotId = &snapshotID
	}

	if vol.IOPS > 0 {
		options.Iops = &vol.IOPS
	}
	var resp *awsec2.Volume

	if resp, err = d.ec2Instance.CreateVolume(options); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"Error creating volume", err)
	}

	if err = d.createTags(*resp.VolumeId, volumeName); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"Error creating tags", err)
	}

	if err = d.waitVolumeComplete(
		ctx, *resp.VolumeId, WaitVolumeCreate); err != nil {
		return &awsec2.Volume{}, goof.WithError(
			"Error waiting for volume creation", err)
	}
	return resp, nil
}

func (d *driver) createVolumeEnsureAvailabilityZone(
	availabilityZone *string, server *awsec2.Instance) {
	if *availabilityZone == "" {
		*availabilityZone = *server.Placement.AvailabilityZone
	}
}

func (d *driver) createTags(id, name string) (err error) {
	var ctInput *awsec2.CreateTagsInput
	initCTInput := func() {
		if ctInput != nil {
			return
		}
		ctInput = &awsec2.CreateTagsInput{
			Resources: []*string{&id},
			Tags:      []*awsec2.Tag{},
		}
	}

	initCTInput()
	ctInput.Tags = append(
		ctInput.Tags,
		&awsec2.Tag{
			Key:   aws.String("Name"),
			Value: &name,
		})

	/*	if d.ec2Tag != "" {
			initCTInput()
			ctInput.Tags = append(
				ctInput.Tags,
				&awsec2.Tag{
					Key:   aws.String(d.rexrayTag()),
					Value: &d.ec2Tag,
				})
		}
	*/
	_, err = d.ec2Instance.CreateTags(ctInput)
	if err != nil {
		return goof.WithError("Error creating tags", err)
	}
	return nil
}

func (d *driver) waitVolumeComplete(
	ctx types.Context, volumeID string, action string) error {
	if volumeID == "" {
		return goof.New("Missing volume ID")
	}

UpdateLoop:
	for {
		volumes, err := d.getVolume(ctx, volumeID, "")
		if err != nil {
			return goof.WithError("Error getting volume", err)
		}

		switch action {
		case WaitVolumeCreate:
			if *volumes[0].State == awsec2.VolumeStateAvailable {
				break UpdateLoop
			}
		case WaitVolumeDetach:
			if len(volumes[0].Attachments) == 0 {
				break UpdateLoop
			}
		case WaitVolumeAttach:
			if len(volumes[0].Attachments) == 1 &&
				*volumes[0].Attachments[0].State == awsec2.VolumeAttachmentStateAttached {
				break UpdateLoop
			}
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}

func (d *driver) waitSnapshotComplete(
	ctx types.Context, snapshotID string) error {
	for {
		snapshots, err := d.getSnapshot(ctx, "", snapshotID, "")
		if err != nil {
			return goof.WithError(
				"Error getting snapshot", err)
		}

		if len(snapshots) == 0 {
			return goof.New("No snapshots found")
		}
		snapshot := snapshots[0]
		if *snapshot.State == awsec2.SnapshotStateCompleted {
			break
		}
		if *snapshot.State == awsec2.SnapshotStateError {
			return goof.Newf("Snapshot state error: %s", *snapshot.StateMessage)
		}
		time.Sleep(1 * time.Second)
	}

	return nil
}

func (d *driver) getName(tags []*awsec2.Tag) string {
	for _, tag := range tags {
		if *tag.Key == "Name" {
			return *tag.Value
		}
	}
	return ""
}

func (d *driver) getInstance() (awsec2.Instance, error) {
	diInput := &awsec2.DescribeInstancesInput{
		InstanceIds: []*string{&d.instanceDocument.InstanceID},
	}
	resp, err := d.ec2Instance.DescribeInstances(diInput)
	if err != nil {
		return awsec2.Instance{}, err
	}

	return *resp.Reservations[0].Instances[0], nil
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

func (d *driver) endpoint() string {
	return d.config.GetString("ec2.endpoint")
}

/*func (d *driver) rexrayTag() string {
	return d.config.GetString("ec2.rexrayTag")
}*/
