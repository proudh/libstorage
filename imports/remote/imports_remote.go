package remote

import (
	// import to load
	_ "github.com/emccode/libstorage/drivers/storage/ec2/storage"
	_ "github.com/emccode/libstorage/drivers/storage/isilon/storage"
	_ "github.com/emccode/libstorage/drivers/storage/scaleio/storage"
	_ "github.com/emccode/libstorage/drivers/storage/vbox/storage"
	_ "github.com/emccode/libstorage/drivers/storage/vfs/storage"
)
