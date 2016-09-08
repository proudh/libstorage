package storage

import (
	/*	"bufio"
		"encoding/json"
		"fmt"
			"io/ioutil"
		"net"
		"net/http"
			"regexp"
		"strings"
		"time"

			log "github.com/Sirupsen/logrus"
	*/
	"github.com/akutz/gofig"
	//	"github.com/akutz/goof"

	//"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	/*	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
		"github.com/aws/aws-sdk-go/aws/ec2metadata"
		"github.com/aws/aws-sdk-go/aws/session"
	*/awsec2 "github.com/aws/aws-sdk-go/service/ec2"

	//	"github.com/emccode/libstorage/api/context"

	"github.com/emccode/libstorage/api/registry"
	"github.com/emccode/libstorage/api/types"
	"github.com/emccode/libstorage/drivers/storage/ebs"
	"github.com/emccode/libstorage/drivers/storage/ec2"
)

type driver struct {
	ebs              types.StorageDriver
	config           gofig.Config
	nextDeviceInfo   *types.NextDeviceInfo
	instanceDocument *instanceIdentityDocument
	ec2Instance      *awsec2.EC2
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
	d.ebs, _ = registry.NewStorageDriver(ebs.Name)
	return d.ebs.Init(context, config)

	/*	d.config = config

		// Initialize with config content for logging
		fields := map[string]interface{}{
			"moduleName": d.Name(),
			"accessKey":  d.accessKey(),
			"region":     d.region(),
			"endpoint":   d.endpoint(),
			"tag":        d.tag(),
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

		// Prepare input for starting new EC2 client with a session
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
		if endpoint == "" && region != "" {
			endpoint = fmt.Sprintf("ec2.%s.amazonaws.com", region)
		}

		maxRetries := d.maxRetries()

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

		awsConfig := aws.NewConfig().WithCredentials(d.awsCreds).WithRegion(region).WithEndpoint(endpoint).WithMaxRetries(maxRetries)

		// Start new EC2 client with config info
		d.ec2Instance = awsec2.New(mySession, awsConfig)

		log.WithFields(fields).Info("storage driver initialized")

		return nil
	*/
}

// NextDeviceInfo returns the information about the driver's next available
// device workflow.
func (d *driver) NextDeviceInfo(
	ctx types.Context) (*types.NextDeviceInfo, error) {
	return d.ebs.NextDeviceInfo(ctx)
	//return d.nextDeviceInfo, nil
}

// Type returns the type of storage the driver provides.
func (d *driver) Type(ctx types.Context) (types.StorageType, error) {
	return d.ebs.Type(ctx)
	//Example: Block storage
	//return types.Block, nil
}

// InstanceInspect returns an instance.
func (d *driver) InstanceInspect(
	ctx types.Context,
	opts types.Store) (*types.Instance, error) {
	return d.ebs.InstanceInspect(ctx, opts)
	/*
		// get instance ID
		iid := context.MustInstanceID(ctx)

		// If no instance ID, return blank instance
		if iid.ID != "" {
			return &types.Instance{InstanceID: iid}, nil
		}

		// Decode metadata from instance ID
		var awsInstanceID string
		if err := iid.UnmarshalMetadata(&awsInstanceID); err != nil {
			return nil, goof.WithError(
				"Error unmarshalling instance id metadata", err)
		}
		instanceID := &types.InstanceID{ID: awsInstanceID, Driver: d.Name()}

		return &types.Instance{InstanceID: instanceID}, nil
	*/
}

// Volumes returns all volumes or a filtered list of volumes.
func (d *driver) Volumes(
	ctx types.Context,
	opts *types.VolumesOpts) ([]*types.Volume, error) {
	return d.ebs.Volumes(ctx, opts)
	/*
		// Get all volumes via EC2 API
		ec2vols, err := d.getVolume(ctx, "", "")
		if err != nil {
			return nil, goof.WithError("Error getting volume", err)
		}
		if len(ec2vols) == 0 {
			return nil, goof.New("no volumes returned")
		}
		// Convert retrieved volumes to libStorage types.Volume
		vols, convErr := d.toTypesVolume(ctx, ec2vols, opts.Attachments)
		if convErr != nil {
			return nil, goof.WithError("Error converting to types.Volume", convErr)
		}
		return vols, nil
	*/
}

// VolumeInspect inspects a single volume.
func (d *driver) VolumeInspect(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeInspectOpts) (*types.Volume, error) {
	return d.ebs.VolumeInspect(ctx, volumeID, opts)
	/*
		// Get volume corresponding to volume ID via EC2 API
		ec2vols, err := d.getVolume(ctx, volumeID, "")
		if err != nil {
			return nil, goof.WithError("Error getting volume", err)
		}
		if len(ec2vols) == 0 {
			return nil, goof.New("no volumes returned")
		}
		vols, convErr := d.toTypesVolume(ctx, ec2vols, opts.Attachments)
		if convErr != nil {
			return nil, goof.WithError("Error converting to types.Volume", convErr)
		}

		// Because getVolume returns an array
		// and we only expect the 1st element to be a match, return 1st element
		return vols[0], nil
	*/
}

// VolumeCreate creates a new volume.
func (d *driver) VolumeCreate(ctx types.Context, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	return d.ebs.VolumeCreate(ctx, volumeName, opts)
	/*
		// Initialize for logging
		fields := map[string]interface{}{
			"driverName": d.Name(),
			"volumeName": volumeName,
			"opts":       opts,
		}

		log.WithFields(fields).Debug("creating volume")

		// Check if volume with same name exists
		ec2vols, err := d.getVolume(ctx, "", volumeName)
		if err != nil {
			return nil, goof.WithFieldsE(fields, "Error getting volume", err)
		}
		volumes, convErr := d.toTypesVolume(ctx, ec2vols, false)
		if convErr != nil {
			return nil, goof.WithFieldsE(fields, "Error converting to types.Volume", convErr)
		}

		if len(volumes) > 0 {
			return nil, goof.WithFields(fields, "volume name already exists")
		}

		volume := &types.Volume{}

		// Pass arguments into libStorage types.Volume
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
		if opts.Encrypted != nil {
			volume.Encrypted = *opts.Encrypted
		}

		// Pass libStorage types.Volume to helper function which calls EC2 API
		vol, err := d.createVolume(ctx, volumeName, "", volume)
		if err != nil {
			return nil, goof.WithFieldsE(fields, "Error creating volume", err)
		}
		// Return the volume created
		return d.VolumeInspect(ctx, *vol.VolumeId, &types.VolumeInspectOpts{
			Attachments: true,
		})
	*/
}

// VolumeCreateFromSnapshot creates a new volume from an existing snapshot.
func (d *driver) VolumeCreateFromSnapshot(
	ctx types.Context,
	snapshotID, volumeName string,
	opts *types.VolumeCreateOpts) (*types.Volume, error) {
	return d.ebs.VolumeCreateFromSnapshot(ctx, snapshotID, volumeName, opts)
	/*
		// Initialize for logging
		fields := map[string]interface{}{
			"driverName": d.Name(),
			"snapshotID": snapshotID,
			"volumeName": volumeName,
			"opts":       opts,
		}

		log.WithFields(fields).Debug("creating volume from snapshot")

		// Check if volume with same name exists
		ec2vols, err := d.getVolume(ctx, "", volumeName)
		if err != nil {
			return nil, goof.WithFieldsE(fields, "Error getting volume", err)
		}
		volumes, convErr := d.toTypesVolume(ctx, ec2vols, false)
		if convErr != nil {
			return nil, goof.WithFieldsE(fields,
				"Error converting to types.Volume", convErr)
		}

		if len(volumes) > 0 {
			return nil, goof.WithFields(fields, "volume name already exists")
		}

		volume := &types.Volume{}

		// Pass arguments into libStorage types.Volume
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
		if *opts.Encrypted == false {
			// Volume must be encrypted if snapshot is encrypted
			snapshot, err := d.SnapshotInspect(ctx, snapshotID, nil)
			if err != nil {
				return &types.Volume{}, goof.WithFieldsE(fields,
					"Error getting snapshot", err)
			}
			volume.Encrypted = snapshot.Encrypted
		} else {
			volume.Encrypted = *opts.Encrypted
		}

		// Pass libStorage types.Volume to helper function which calls EC2 API
		vol, err := d.createVolume(ctx, volumeName, snapshotID, volume)
		if err != nil {
			return &types.Volume{}, goof.WithFieldsE(fields,
				"error creating volume", err)
		}
		// Return the volume created
		return d.VolumeInspect(ctx, *vol.VolumeId, &types.VolumeInspectOpts{
			Attachments: true,
		})
	*/
}

// VolumeCopy copies an existing volume.
func (d *driver) VolumeCopy(
	ctx types.Context,
	volumeID, volumeName string,
	opts types.Store) (*types.Volume, error) {
	return d.ebs.VolumeCopy(ctx, volumeID, volumeName, opts)
	/*
		var (
			ec2vols  []*awsec2.Volume
			err      error
			snapshot *types.Snapshot
			vol      *types.Volume
		)

		// Initialize for logging
		fields := map[string]interface{}{
			"driverName": d.Name(),
			"volumeID":   volumeID,
			"volumeName": volumeName,
			"opts":       opts,
		}

		log.WithFields(fields).Debug("creating volume from snapshot")

		// Check if volume with same name exists
		ec2VolsToCheck, err := d.getVolume(ctx, "", volumeName)
		if err != nil {
			return nil, goof.WithFieldsE(fields, "Error getting volume", err)
		}
		volsToCheck, convErr := d.toTypesVolume(ctx, ec2VolsToCheck, false)
		if convErr != nil {
			return nil, goof.WithFieldsE(fields, "Error converting to types.Volume",
				convErr)
		}

		if len(volsToCheck) > 0 {
			return nil, goof.WithFields(fields, "volume name already exists")
		}

		// Get volume to copy using volumeID
		ec2vols, err = d.getVolume(ctx, volumeID, "")
		if err != nil {
			return &types.Volume{}, goof.WithFieldsE(fields,
				"error getting volume", err)
		}
		volumes, convErr2 := d.toTypesVolume(ctx, ec2vols, false)
		if convErr2 != nil {
			return nil, goof.WithFieldsE(fields,
				"Error converting to types.Volume", convErr2)
		}
		if len(volumes) > 1 {
			return &types.Volume{},
				goof.WithFields(fields, "multiple volumes returned")
		} else if len(volumes) == 0 {
			return &types.Volume{}, goof.WithFields(fields, "no volumes returned")
		}

		// Create temporary snapshot
		snapshotName := fmt.Sprintf("temp-%s-%d", volumeID, time.Now().UnixNano())
		fields["snapshotName"] = snapshotName
		snapshot, err = d.VolumeSnapshot(ctx, volumeID, snapshotName, opts)
		if err != nil {
			return &types.Volume{}, goof.WithFieldsE(fields,
				"error creating temporary snapshot", err)
		}

		// Use temporary snapshot to create volume
		vol, err = d.VolumeCreateFromSnapshot(ctx, snapshot.ID,
			volumeName, &types.VolumeCreateOpts{Encrypted: &snapshot.Encrypted,
				Opts: opts})
		if err != nil {
			return &types.Volume{}, goof.WithFieldsE(fields,
				"error creating volume copy from snapshot", err)
		}

		// Remove temporary snapshot created
		if err = d.SnapshotRemove(ctx, snapshot.ID, opts); err != nil {
			return &types.Volume{}, goof.WithFieldsE(fields,
				"error removing temporary snapshot", err)
		}

		log.Println("Created volume " + vol.ID + " from volume " + volumeID)
		return vol, nil
	*/
}

// VolumeSnapshot snapshots a volume.
func (d *driver) VolumeSnapshot(
	ctx types.Context,
	volumeID, snapshotName string,
	opts types.Store) (*types.Snapshot, error) {
	return d.ebs.VolumeSnapshot(ctx, volumeID, snapshotName, opts)
	/*
		// Create snapshot with EC2 API call
		csInput := &awsec2.CreateSnapshotInput{
			VolumeId: &volumeID,
		}

		resp, err := d.ec2Instance.CreateSnapshot(csInput)
		if err != nil {
			return nil, goof.WithError("Error creating snapshot", err)
		}

		// Add tags to EC2 snapshot
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

		// Check if successful snapshot
		snapshot, err := d.SnapshotInspect(ctx, *resp.SnapshotId, nil)
		if err != nil {
			return &types.Snapshot{}, goof.WithError(
				"Error getting snapshot", err)
		}

		log.Println("Created Snapshot: " + snapshot.ID)
		return snapshot, nil
	*/
}

// VolumeRemove removes a volume.
func (d *driver) VolumeRemove(
	ctx types.Context,
	volumeID string,
	opts types.Store) error {
	return d.ebs.VolumeRemove(ctx, volumeID, opts)
	/*
		// Initialize for logging
		fields := map[string]interface{}{
			"provider": d.Name(),
			"volumeID": volumeID,
		}

		//TODO check if volume is attached? if so fail

		// Delete volume via EC2 API call
		dvInput := &awsec2.DeleteVolumeInput{
			VolumeId: &volumeID,
		}
		_, err := d.ec2Instance.DeleteVolume(dvInput)
		if err != nil {
			return goof.WithFieldsE(fields, "error deleting volume", err)
		}

		return nil
	*/
}

// VolumeAttach attaches a volume and provides a token clients can use
// to validate that device has appeared locally.
func (d *driver) VolumeAttach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeAttachOpts) (*types.Volume, string, error) {
	return d.ebs.VolumeAttach(ctx, volumeID, opts)
	/*
		nextDeviceName, err := d.GetNextAvailableDeviceName()
		if err != nil {
			return nil, "", goof.WithError(
				"Error getting next available device name", err)
		}

		// review volume with attachments to any host
		ec2vols, err := d.getVolume(ctx, volumeID, "")
		if err != nil {
			return nil, "", goof.WithError("Error getting volume", err)
		}
		volumes, convErr := d.toTypesVolume(ctx, ec2vols, true)
		if convErr != nil {
			return nil, "", goof.WithError(
				"Error converting to types.Volume", convErr)
		}

		// Check if there a volume to attach
		if len(volumes) == 0 {
			return nil, "", goof.New("no volume found")
		}
		// Check if volume is already attached
		if len(volumes[0].Attachments) > 0 && !opts.Force {
			return nil, "", goof.New("volume already attached to a host")
		}
		// Detach already attached volume if forced
		if opts.Force {
			if _, err := d.VolumeDetach(ctx, volumeID, nil); err != nil {
				return nil, "", goof.WithError("Error detaching volume", err)
			}
		}

		// Attach volume via helper function which uses EC2 API call
		err = d.attachVolume(ctx, volumeID, volumes[0].Name, nextDeviceName)
		if err != nil {
			return nil, "", goof.WithFieldsE(
				log.Fields{
					"provider": d.Name(),
					"volumeID": volumeID},
				"error attaching volume",
				err,
			)
		}

		// Wait for volume's status to update
		if err = d.waitVolumeComplete(ctx, volumeID, waitVolumeAttach); err != nil {
			return nil, "", goof.WithError("error waiting for volume attach", err)
		}

		// Check if successful attach
		attachedVol, err := d.VolumeInspect(
			ctx, volumeID, &types.VolumeInspectOpts{
				Attachments: true,
				Opts:        opts.Opts,
			})
		if err != nil {
			return nil, "", goof.WithError("error getting volume", err)
		}

		// Token is the attachment's device name
		return attachedVol, attachedVol.Attachments[0].DeviceName, nil
	*/
}

// VolumeDetach detaches a volume.
func (d *driver) VolumeDetach(
	ctx types.Context,
	volumeID string,
	opts *types.VolumeDetachOpts) (*types.Volume, error) {
	return d.ebs.VolumeDetach(ctx, volumeID, opts)
	/*
		// review volume with attachments to any host
		ec2vols, err := d.getVolume(ctx, volumeID, "")
		if err != nil {
			return nil, goof.WithError("Error getting volume", err)
		}
		volumes, convErr := d.toTypesVolume(ctx, ec2vols, true)
		if convErr != nil {
			return nil, goof.WithError("Error converting to types.Volume", convErr)
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

		// Detach volume using EC2 API call
		if _, err = d.ec2Instance.DetachVolume(dvInput); err != nil {
			return nil, goof.WithFieldsE(
				log.Fields{
					"provider": d.Name(),
					"volumeID": volumeID}, "error detaching volume", err)
		}

		if err = d.waitVolumeComplete(ctx, volumeID, waitVolumeDetach); err != nil {
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
	*/
}

// Snapshots returns all volumes or a filtered list of snapshots.
func (d *driver) Snapshots(
	ctx types.Context,
	opts types.Store) ([]*types.Snapshot, error) {
	return d.ebs.Snapshots(ctx, opts)
	/*
		// Get all snapshots
		ec2snapshots, err := d.getSnapshot(ctx, "", "", "")
		if err != nil {
			return nil, goof.WithError("error getting snapshot", err)
		}
		if len(ec2snapshots) == 0 {
			return nil, goof.New("no snapshots returned")
		}
		// Convert to libStorage types.Snapshot
		snapshots := d.toTypesSnapshot(ec2snapshots)
		return snapshots, nil
	*/
}

// SnapshotInspect inspects a single snapshot.
func (d *driver) SnapshotInspect(
	ctx types.Context,
	snapshotID string,
	opts types.Store) (*types.Snapshot, error) {
	return d.ebs.SnapshotInspect(ctx, snapshotID, opts)
	/*
		// Get snapshot corresponding to snapshot ID
		ec2snapshots, err := d.getSnapshot(ctx, "", snapshotID, "")
		if err != nil {
			return nil, goof.WithError("error getting snapshot", err)
		}
		if len(ec2snapshots) == 0 {
			return nil, goof.New("no snapshots returned")
		}
		// Convert to libStorage types.Snapshot
		snapshots := d.toTypesSnapshot(ec2snapshots)

		// Because getSnapshot returns an array
		// and we only expect the 1st element to be a match, return 1st element
		return snapshots[0], nil
	*/
}

// SnapshotCopy copies an existing snapshot.
func (d *driver) SnapshotCopy(
	ctx types.Context,
	snapshotID, snapshotName, destinationID string,
	opts types.Store) (*types.Snapshot, error) {
	return d.ebs.SnapshotCopy(ctx, snapshotID, snapshotName, destinationID, opts)
	/*
		// no snapshot id inputted
		if snapshotID == "" {
			return &types.Snapshot{}, goof.New("Missing snapshotID")
		}

		// Get snapshot to copy
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

		// Copy snapshot with EC2 API call
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
			return nil, goof.WithError("error copying snapshot", err)
		}

		// Add tags to copied snapshot
		if err = d.createTags(*resp.SnapshotId, snapshotName); err != nil {
			return &types.Snapshot{}, goof.WithError(
				"Error creating tags", err)
		}

		log.WithFields(log.Fields{
			"moduleName":      d.Name(),
			"driverName":      d.Name(),
			"snapshotName":    snapshotName,
			"resp.SnapshotId": *resp.SnapshotId}).Info("waiting for snapshot to complete")

		// Wait for snapshot status to update
		err = d.waitSnapshotComplete(ctx, *resp.SnapshotId)
		if err != nil {
			return &types.Snapshot{}, goof.WithError(
				"Error waiting for snapshot creation", err)
		}

		// Check if successful snapshot
		snapshotCopy, err := d.SnapshotInspect(ctx, *resp.SnapshotId, nil)
		if err != nil {
			return &types.Snapshot{}, goof.WithError(
				"Error getting snapshot copy", err)
		}
		destinationID = snapshotCopy.ID

		log.Println("Copied Snapshot: " + destinationID)
		return snapshotCopy, nil
	*/
}

// SnapshotRemove removes a snapshot.
func (d *driver) SnapshotRemove(
	ctx types.Context,
	snapshotID string,
	opts types.Store) error {
	return d.ebs.SnapshotRemove(ctx, snapshotID, opts)
	/*
		// Initialize for logging
		fields := map[string]interface{}{
			"provider":   d.Name(),
			"snapshotID": snapshotID,
		}

		// no snapshot ID inputted
		if snapshotID == "" {
			return goof.New("missing snapshot id")
		}

		// Delete snapshot using EC2 API call
		dsInput := &awsec2.DeleteSnapshotInput{
			SnapshotId: &snapshotID,
		}
		_, err := d.ec2Instance.DeleteSnapshot(dsInput)
		if err != nil {
			return goof.WithFieldsE(fields, "error deleting snapshot", err)
		}

		return nil
	*/
}
