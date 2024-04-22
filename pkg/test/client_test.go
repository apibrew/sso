package test

import (
	"github.com/apibrew/apibrew/pkg/service"
	"github.com/apibrew/apibrew/pkg/service/impl"
	"github.com/apibrew/apibrew/pkg/stub"
	"github.com/apibrew/apibrew/pkg/test/setup"
	sso2 "github.com/apibrew/sso/pkg"
)

var recordClient stub.RecordClient

var container service.Container

func init() {
	recordClient = setup.RecordClient
	container = setup.GetContainer()

	container.(*impl.App).RegisterModule(sso2.NewModule)
}
