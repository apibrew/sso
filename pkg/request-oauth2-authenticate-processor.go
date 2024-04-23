package sso

import (
	"github.com/apibrew/apibrew/pkg/api"
	"github.com/apibrew/apibrew/pkg/errors"
	"github.com/apibrew/apibrew/pkg/util"
	model2 "github.com/apibrew/sso/pkg/model"
)

type requestOauth2AuthenticateProcessor struct {
	api                    api.Interface
	op                     *oauth2Provider
	oauth2ConfigRepository api.Repository[*model2.Oauth2Config]
}

func (r requestOauth2AuthenticateProcessor) Mapper() Mapper[*model2.Oauth2Authenticate] {
	return model2.Oauth2AuthenticateMapperInstance
}

func (r requestOauth2AuthenticateProcessor) Register(entity *model2.Oauth2Authenticate) error {
	// load
	if err := r.load(entity); err != nil {
		return err
	}

	var token, err = r.op.Authenticate(entity.Config, entity.Code)

	if err != nil {
		return err
	}

	entity.Config = &model2.Oauth2Config{
		Name: entity.Config.Name,
		Provider: &model2.Oauth2Provider{
			Name: entity.Config.Provider.Name,
		},
	}

	entity.Token = util.Pointer(token)

	return nil
}

func (r requestOauth2AuthenticateProcessor) load(entity *model2.Oauth2Authenticate) error {
	config, err := r.oauth2ConfigRepository.Load(util.SystemContext, entity.Config, api.LoadParams{
		ResolveReferences: []string{"$.provider"},
	})

	if err != nil {
		return err
	}

	entity.Config = config

	return nil
}

func (r requestOauth2AuthenticateProcessor) Update(entity *model2.Oauth2Authenticate) error {
	return errors.RecordValidationError.WithMessage("Update not supported")
}

func (r requestOauth2AuthenticateProcessor) UnRegister(entity *model2.Oauth2Authenticate) error {
	return errors.RecordValidationError.WithMessage("Delete not supported")
}
