package ec2

import (
	//	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/akutz/gofig"
	"github.com/stretchr/testify/assert"

	"github.com/emccode/libstorage/api/context"
	"github.com/emccode/libstorage/api/registry"
	"github.com/emccode/libstorage/api/server"
	apitests "github.com/emccode/libstorage/api/tests"
	"github.com/emccode/libstorage/api/types"
	"github.com/emccode/libstorage/api/utils"
	"github.com/emccode/libstorage/drivers/storage/ec2"
	ec2x "github.com/emccode/libstorage/drivers/storage/ec2/executor"
)

// Put contents of sample config.yml here
var (
	configYAML = []byte(`
ec2:
  tag: integrationtest
  region: us-west-2
  securityGroups: minecraft-server-group
  accessKey: ` + os.Getenv("AWS_ACCESS_KEY_ID") + `
  secretKey: ` + os.Getenv("AWS_SECRET_ACCESS_KEY"))
)

var volumeName string
var volumeName2 string

// Check environment vars to see whether or not to run this test
func skipTests() bool {
	travis, _ := strconv.ParseBool(os.Getenv("TRAVIS"))
	noTest, _ := strconv.ParseBool(os.Getenv("TEST_SKIP_EC2"))
	return travis || noTest
}

// Set volume names to first part of UUID before the -
func init() {
	uuid, _ := types.NewUUID()
	uuids := strings.Split(uuid.String(), "-")
	volumeName = uuids[0]
	uuid, _ = types.NewUUID()
	uuids = strings.Split(uuid.String(), "-")
	volumeName2 = uuids[0]
}

func TestMain(m *testing.M) {
	server.CloseOnAbort()
	ec := m.Run()
	os.Exit(ec)
}

// Isilon and ScaleIO just check result of InstanceID();
// VBox and EFS fill in InstanceID completely then check it
func TestInstanceID(t *testing.T) {
	// create storage driver
	sd, err := registry.NewStorageDriver(ec2.Name)
	if err != nil {
		t.Fatal(err)
	}

	// initialize storage driver
	ctx := context.Background()
	if err := sd.Init(ctx, gofig.New()); err != nil {
		t.Fatal(err)
	}

	// Get Instance ID
	iid, err := ec2x.InstanceID()
	assert.NoError(t, err)
	if err != nil {
		t.Fatal(err)
	}

	// Fill in Instance ID's ID field with InstanceInspect
	ctx = ctx.WithValue(context.InstanceIDKey, iid)
	i, err := sd.InstanceInspect(ctx, utils.NewStore())
	if err != nil {
		t.Fatal(err)
	}

	iid = i.InstanceID

	// test resulting InstanceID
	apitests.Run(
		t, ec2.Name, nil,
		(&apitests.InstanceIDTest{
			Driver:   ec2.Name,
			Expected: iid,
		}).Test)

}

// same everywhere
func TestServices(t *testing.T) {
	/*if skipTests() {
		t.SkipNow()
	}

	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		reply, err := client.API().Services(nil)
		assert.NoError(t, err)
		assert.Equal(t, len(reply), 1)

		_, ok := reply[ec2.Name]
		assert.True(t, ok)
	}
	apitests.Run(t, ec2.Name, configYAML, tf)
	*/
}

//same everywhere
func volumeCreate(
	t *testing.T, client types.Client, volumeName string) *types.Volume {
	return nil
	/*
		log.WithField("volumeName", volumeName).Info("creating volume")
		size := int64(8)

		opts := map[string]interface{}{
			"priority": 2,
			"owner":    "root@example.com",
		}

		volumeCreateRequest := &types.VolumeCreateRequest{
			Name: volumeName,
			Size: &size,
			Opts: opts,
		}

		reply, err := client.API().VolumeCreate(nil, ec2.Name, volumeCreateRequest)
		assert.NoError(t, err)
		if err != nil {
			//TODO can do t.Fatal("failed volumeCreate") instead?
			t.FailNow()
			t.Error("failed volumeCreate")
		}
		apitests.LogAsJSON(reply, t)

		assert.Equal(t, volumeName, reply.Name)
		assert.Equal(t, size, reply.Size)
		return reply
	*/
}

// same everywhere
func volumeByName(
	t *testing.T, client types.Client, volumeName string) *types.Volume {
	log.WithField("volumeName", volumeName).Info("get volume by ec2.Name")
	vols, err := client.API().Volumes(nil, false)
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}
	assert.Contains(t, vols, ec2.Name)
	for _, vol := range vols[ec2.Name] {
		if vol.Name == volumeName {
			return vol
		}
	}
	t.FailNow()
	t.Error("failed volumeByName")
	return nil
}

// same everywhere
func TestVolumeCreateRemove(t *testing.T) {
	/*	if skipTests() {
			t.SkipNow()
		}

		tf := func(config gofig.Config, client types.Client, t *testing.T) {
			vol := volumeCreate(t, client, volumeName)
			volumeRemove(t, client, vol.ID)
		}
		apitests.Run(t, ec2.Name, configYAML, tf)
	*/
}

func volumeRemove(t *testing.T, client types.Client, volumeID string) {
	/*	log.WithField("volumeID", volumeID).Info("removing volume")
		err := client.API().VolumeRemove(
			nil, ec2.Name, volumeID)
		assert.NoError(t, err)

		if err != nil {
			// TODO t.Fatal("failed volumeRemove")
			t.Error("failed volumeRemove")
			t.FailNow()
		}
	*/
}

// same everywhere
func TestVolumes(t *testing.T) {
	/*	if skipTests() {
			t.SkipNow()
		}

		tf := func(config gofig.Config, client types.Client, t *testing.T) {
			_ = volumeCreate(t, client, volumeName)
			_ = volumeCreate(t, client, volumeName2)

			vol1 := volumeByName(t, client, volumeName)
			vol2 := volumeByName(t, client, volumeName2)

			volumeRemove(t, client, vol1.ID)
			volumeRemove(t, client, vol2.ID)
		}
		apitests.Run(t, ec2.Name, configYAML, tf)
	*/
}

// same everywhere
func volumeAttach(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	return nil
	/*
		log.WithField("volumeID", volumeID).Info("attaching volume")
		reply, token, err := client.API().VolumeAttach(
			nil, ec2.Name, volumeID, &types.VolumeAttachRequest{})

		assert.NoError(t, err)
		if err != nil {
			// TODO t.Fatal("failed volumeAttach")
			t.Error("failed volumeAttach")
			t.FailNow()
		}
		apitests.LogAsJSON(reply, t)
		assert.NotEqual(t, token, "")

		return reply
	*/
}

// same everywhere - omitted in EFS
func volumeInspect(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	log.WithField("volumeID", volumeID).Info("inspecting volume")
	reply, err := client.API().VolumeInspect(nil, ec2.Name, volumeID, false)
	assert.NoError(t, err)

	if err != nil {
		t.Error("failed volumeInspect")
		t.FailNow()
	}
	apitests.LogAsJSON(reply, t)
	return reply
}

// same everywhere
func volumeInspectAttached(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	return nil
	/*
		log.WithField("volumeID", volumeID).Info("inspecting volume")
		reply, err := client.API().VolumeInspect(nil, ec2.Name, volumeID, true)
		assert.NoError(t, err)

		if err != nil {
			t.Error("failed volumeInspectAttached")
			t.FailNow()
		}
		apitests.LogAsJSON(reply, t)
		assert.Len(t, reply.Attachments, 1)
		return reply
	*/
}

// same everywhere - omitted in EFS
func volumeInspectAttachedFail(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	return nil
	/*
		log.WithField("volumeID", volumeID).Info("inspecting volume")
		reply, err := client.API().VolumeInspect(nil, ec2.Name, volumeID, true)
		assert.NoError(t, err)

		if err != nil {
			t.Error("failed volumeInspectAttachedFail")
			t.FailNow()
		}
		apitests.LogAsJSON(reply, t)
		assert.Len(t, reply.Attachments, 0)
		return reply
	*/
}

// same everywhere
func volumeInspectDetached(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	return nil
	/*
		log.WithField("volumeID", volumeID).Info("inspecting volume")
		reply, err := client.API().VolumeInspect(nil, ec2.Name, volumeID, true)
		assert.NoError(t, err)

		if err != nil {
			t.Error("failed volumeInspectDetached")
			t.FailNow()
		}
		apitests.LogAsJSON(reply, t)
		assert.Len(t, reply.Attachments, 0)
		apitests.LogAsJSON(reply, t)
		return reply
	*/
}

// same in vbox but omitted in isilon and EFS
func volumeInspectDetachedFail(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	return nil
	/*
		log.WithField("volumeID", volumeID).Info("inspecting volume")
		reply, err := client.API().VolumeInspect(nil, ec2.Name, volumeID, false)
		assert.NoError(t, err)

		if err != nil {
			t.Error("failed volumeInspectDetachedFail")
			t.FailNow()
		}
		apitests.LogAsJSON(reply, t)
		assert.Len(t, reply.Attachments, 1)
		apitests.LogAsJSON(reply, t)
		return reply
	*/
}

// same everywhere
func volumeDetach(
	t *testing.T, client types.Client, volumeID string) *types.Volume {
	log.WithField("volumeID", volumeID).Info("detaching volume")
	return nil
	/*		reply, err := client.API().VolumeDetach(
				nil, ec2.Name, volumeID, &types.VolumeDetachRequest{})
			assert.NoError(t, err)
			if err != nil {
				t.Error("failed volumeDetach")
				t.FailNow()
			}
			apitests.LogAsJSON(reply, t)
			assert.Len(t, reply.Attachments, 0)
			return reply
	*/
}

// same everywhere but use apitests.RunGroup
func TestVolumeAttach(t *testing.T) {
	/*	if skipTests() {
			t.SkipNow()
		}
		var vol *types.Volume
		tf := func(config gofig.Config, client types.Client, t *testing.T) {
			vol = volumeCreate(t, client, volumeName)
			_ = volumeAttach(t, client, vol.ID)
			_ = volumeInspectAttached(t, client, vol.ID)
			_ = volumeInspectDetachedFail(t, client, vol.ID)
			_ = volumeDetach(t, client, vol.ID)
			_ = volumeInspectDetached(t, client, vol.ID)
			volumeRemove(t, client, vol.ID)
		}
		apitests.Run(t, ec2.Name, configYAML, tf)
	*/
}

// mini tests
func TestVolumeInspect(t *testing.T) {
	if skipTests() {
		t.SkipNow()
	}
	tf := func(config gofig.Config, client types.Client, t *testing.T) {
		_ = volumeByName(t, client, "mc-server-volume")
		_ = volumeInspect(t, client, "vol-992ca510")
	}
	apitests.Run(t, ec2.Name, configYAML, tf)
}
