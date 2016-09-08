package ebs

import (
	"github.com/akutz/gofig"
)

const (
	// Name is the provider's name.
	Name = "ebs"
)

func init() {
	registerConfig()
}

func registerConfig() {
	r := gofig.NewRegistration("Amazon EC2 EBS")
	r.Key(gofig.String, "", "", "", "ebs.accessKey")
	r.Key(gofig.String, "", "", "", "ebs.secretKey")
	r.Key(gofig.String, "", "", "", "ebs.region")
	r.Key(gofig.String, "", "", "", "ebs.endpoint")
	r.Key(gofig.String, "", "", "", "ebs.maxRetries")
	r.Key(gofig.String, "", "", "Tag prefix for EBS naming", "ebs.tag")
	gofig.Register(r)
}
