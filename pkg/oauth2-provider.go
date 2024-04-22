package sso

import (
	"context"
	"encoding/json"
	errors "errors"
	"github.com/apibrew/apibrew/pkg/api"
	"github.com/apibrew/apibrew/pkg/formats/unstructured"
	"github.com/apibrew/apibrew/pkg/model"
	"github.com/apibrew/apibrew/pkg/service"
	"github.com/apibrew/apibrew/pkg/util"
	model2 "github.com/apibrew/sso/pkg/model"
	"golang.org/x/oauth2"
	"io"
	"net/http"
)

type oauth2Provider struct {
	container service.Container
	api       api.Interface
}

func (p oauth2Provider) RequestCode(config *model2.Oauth2Config) (string, error) {
	oauth2Config := p.prepareOauth2Config(config)

	url := oauth2Config.AuthCodeURL("state-token")

	return url, nil
}

func (p oauth2Provider) prepareOauth2Config(config *model2.Oauth2Config) *oauth2.Config {
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientId,
		ClientSecret: config.ClientSecret,
		RedirectURL:  util.DePointer(config.RedirectUrl, ""),
		Scopes:       config.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   config.Provider.AuthUrl,
			TokenURL:  config.Provider.TokenUrl,
			AuthStyle: 0,
		},
	}
	return oauth2Config
}

func (p oauth2Provider) Authenticate(config *model2.Oauth2Config, code string) (string, error) {
	oauth2Config := p.prepareOauth2Config(config)

	token, err := oauth2Config.Exchange(context.Background(), code)

	if err != nil {
		return "", err
	}

	request, err := http.NewRequest("GET", config.Provider.UserInfoUrl, nil)

	if err != nil {
		return "", err
	}

	request.Header.Set("Authorization", "Bearer "+token.AccessToken)

	client := &http.Client{}

	response, err := client.Do(request)

	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	var userInfo map[string]interface{}

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	err = json.Unmarshal(body, &userInfo)

	if err != nil {
		return "", err
	}

	var username, ok = userInfo[util.DePointer(config.Provider.UserInfoExtractConfig.Username, "")].(string)

	if !ok {
		return "", errors.New("username not found in user info")
	}

	if username == "" {
		return "", errors.New("username not found in user info")
	}

	token2, err2 := p.container.GetAuthenticationService().AuthenticateWithoutPassword(util.SystemContext, username, model.TokenTerm_LONG)

	if err2 != nil {
		_, err = p.api.Create(util.SystemContext, unstructured.Unstructured{
			"type":     "system/User",
			"username": username,
			"password": util.RandomHex(16),
			"roles": util.ArrayMap(config.NewUserRoles, func(t string) unstructured.Unstructured {
				return unstructured.Unstructured{
					"name": t,
				}
			}),
			"details": userInfo,
		})

		if err != nil {
			return "", err
		}

		token2, err2 := p.container.GetAuthenticationService().AuthenticateWithoutPassword(util.SystemContext, username, model.TokenTerm_LONG)

		if err2 != nil {
			return "", err2
		}

		return token2.Content, nil
	}

	return token2.Content, nil
}
