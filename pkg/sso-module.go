package sso

import (
	"github.com/apibrew/apibrew/pkg/api"
	"github.com/apibrew/apibrew/pkg/errors"
	"github.com/apibrew/apibrew/pkg/model"
	"github.com/apibrew/apibrew/pkg/resources"
	"github.com/apibrew/apibrew/pkg/service"
	backend_event_handler "github.com/apibrew/apibrew/pkg/service/backend-event-handler"
	"github.com/apibrew/apibrew/pkg/util"
	model2 "github.com/apibrew/sso/pkg/model"
	"golang.org/x/oauth2/endpoints"
	"google.golang.org/protobuf/types/known/structpb"
	"log"
)

type module struct {
	container           service.Container
	backendEventHandler backend_event_handler.BackendEventHandler
	api                 api.Interface
	op                  *oauth2Provider
}

func (m module) Init() {
	m.ensureNamespace()
	m.ensureResources()

	if err := RegisterResourceProcessor[*model2.Oauth2Request](
		"sso-oauth2-request-listener",
		&requestOauth2CodeProcessor{
			api: m.api,
			op:  m.op,
		},
		m.backendEventHandler,
		m.container,
		model2.Oauth2RequestResource,
	); err != nil {
		log.Fatal(err)
	}

	if err := RegisterResourceProcessor[*model2.Oauth2Authenticate](
		"sso-oauth2-authenticate-listener",
		&requestOauth2AuthenticateProcessor{
			api: m.api,
			op:  m.op,
		},
		m.backendEventHandler,
		m.container,
		model2.Oauth2AuthenticateResource,
	); err != nil {
		log.Fatal(err)
	}

	m.initDefaultProviders()
}

func (m module) ensureNamespace() {
	_, err := m.container.GetRecordService().Apply(util.SystemContext, service.RecordUpdateParams{
		Namespace: resources.NamespaceResource.Namespace,
		Resource:  resources.NamespaceResource.Name,
		Records: []*model.Record{
			{
				Properties: map[string]*structpb.Value{
					"name": structpb.NewStringValue("sso"),
				},
			},
		},
	})

	if err != nil {
		log.Fatal(err)
	}
}

func (m module) ensureResources() {
	var list = []*model.Resource{
		model2.Oauth2ProviderResource,
		model2.Oauth2ConfigResource,
		model2.Oauth2RequestResource,
		model2.Oauth2AuthenticateResource,
	}

	for _, resource := range list {
		existingResource, err := m.container.GetResourceService().GetResourceByName(util.SystemContext, resource.Namespace, resource.Name)

		if err == nil {
			resource.Id = existingResource.Id
			err = m.container.GetResourceService().Update(util.SystemContext, resource, true, true)

			if err != nil {
				log.Fatal(err)
			}
		} else if err.Is(errors.ResourceNotFoundError) {
			_, err = m.container.GetResourceService().Create(util.SystemContext, resource, true, true)

			if err != nil {
				log.Fatal(err)
			}
		} else {
			log.Fatal(err)
		}
	}
}

func (m module) initDefaultProviders() {
	var defaultProviders = []*model2.Oauth2Provider{
		{
			Name:        "Amazon",
			AuthUrl:     endpoints.Amazon.AuthURL,
			TokenUrl:    endpoints.Amazon.TokenURL,
			UserInfoUrl: "https://api.amazon.com/user/profile",
			UserInfoExtractConfig: &model2.Oauth2ProviderUserInfoExtract{
				Username: util.Pointer("email"),
			},
			DefaultScopes: []string{"profile"},
		},
		{
			Name:        "Google",
			AuthUrl:     endpoints.Google.AuthURL,
			TokenUrl:    endpoints.Google.TokenURL,
			UserInfoUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
			UserInfoExtractConfig: &model2.Oauth2ProviderUserInfoExtract{
				Username: util.Pointer("email"),
			},
			DefaultScopes: []string{"profile"},
		},
		{
			Name:        "Github",
			AuthUrl:     endpoints.GitHub.AuthURL,
			TokenUrl:    endpoints.GitHub.TokenURL,
			UserInfoUrl: "https://api.github.com/user",
			UserInfoExtractConfig: &model2.Oauth2ProviderUserInfoExtract{
				Username: util.Pointer("email"),
			},
			DefaultScopes: []string{"user:email"},
		},
		{
			Name:        "Facebook",
			AuthUrl:     endpoints.Facebook.AuthURL,
			TokenUrl:    endpoints.Facebook.TokenURL,
			UserInfoUrl: "https://graph.facebook.com/v3.2/me",
			UserInfoExtractConfig: &model2.Oauth2ProviderUserInfoExtract{
				Username: util.Pointer("email"),
			},
			DefaultScopes: []string{"email"},
		},
	}

	for _, provider := range defaultProviders {
		_, err := m.api.Apply(util.SystemContext, model2.Oauth2ProviderMapperInstance.ToUnstructured(provider))

		if err != nil {
			log.Fatal(err)
		}
	}
}

func NewModule(container service.Container) service.Module {
	a := api.NewInterface(container)

	backendEventHandler := container.GetBackendEventHandler().(backend_event_handler.BackendEventHandler)
	return &module{container: container,
		api:                 a,
		op:                  &oauth2Provider{container: container, api: a},
		backendEventHandler: backendEventHandler}
}
