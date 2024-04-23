package sso

import (
	"github.com/apibrew/apibrew/pkg/api"
	"github.com/apibrew/apibrew/pkg/errors"
	"github.com/apibrew/apibrew/pkg/formats/unstructured"
	"github.com/apibrew/apibrew/pkg/util"
	model2 "github.com/apibrew/sso/pkg/model"
)

type requestOauth2CodeProcessor struct {
	api                    api.Interface
	op                     *oauth2Provider
	oauth2ConfigRepository api.Repository[*model2.Oauth2Config]
}

func (r requestOauth2CodeProcessor) Mapper() Mapper[*model2.Oauth2Request] {
	return model2.Oauth2RequestMapperInstance
}

func (r requestOauth2CodeProcessor) Register(entity *model2.Oauth2Request) error {
	// load
	if err := r.load(entity); err != nil {
		return err
	}

	var redirectUrl, err = r.op.RequestCode(entity.Config)

	if err != nil {
		return err
	}

	entity.RedirectUrl = util.Pointer(redirectUrl)
	entity.Config = &model2.Oauth2Config{
		Name: entity.Config.Name,
		Provider: &model2.Oauth2Provider{
			Name: entity.Config.Provider.Name,
		},
	}

	return nil
}

func (r requestOauth2CodeProcessor) load(entity *model2.Oauth2Request) error {
	var oauth2ConfigToLoad = model2.Oauth2ConfigMapperInstance.ToUnstructured(entity.Config)

	oauth2ConfigToLoadRes, err := r.api.Load(util.SystemContext, oauth2ConfigToLoad, api.LoadParams{
		ResolveReferences: []string{"$.provider"},
	})

	if err != nil {
		return err
	}

	record, err2 := unstructured.ToRecord(oauth2ConfigToLoadRes)

	if err2 != nil {
		return err2
	}

	var oauth2Config = model2.Oauth2ConfigMapperInstance.FromRecord(record)

	entity.Config = oauth2Config

	return nil
}

func (r requestOauth2CodeProcessor) Update(entity *model2.Oauth2Request) error {
	return errors.RecordValidationError.WithMessage("Update not supported")
}

func (r requestOauth2CodeProcessor) UnRegister(entity *model2.Oauth2Request) error {
	return errors.RecordValidationError.WithMessage("Delete not supported")
}
