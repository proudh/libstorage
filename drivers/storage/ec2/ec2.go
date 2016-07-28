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
	r.Key(gofig.String, "", "", "", "aws.accessKey")
	r.Key(gofig.String, "", "", "", "aws.secretKey")
	r.Key(gofig.String, "", "", "", "aws.region")
	r.Key(gofig.String, "", "", "", "aws.rexrayTag")
	gofig.Register(r)
}

