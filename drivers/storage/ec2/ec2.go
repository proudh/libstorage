package ec2

import (
	"github.com/akutz/gofig"
)

const (
	// Name is the provider's name.
	Name = "ec2"
)

func init() {
	registerConfig()
}

func registerConfig() {
	r := gofig.NewRegistration("Amazon EC2")
	r.Key(gofig.String, "", "", "", "ec2.accessKey")
	r.Key(gofig.String, "", "", "", "ec2.secretKey")
	r.Key(gofig.String, "", "", "", "ec2.region")
	r.Key(gofig.String, "", "", "", "ec2.rexrayTag")
	gofig.Register(r)
}

