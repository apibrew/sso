package sso

//go:generate apbr generate --platform=golang --path=./model/ --package=model --source-file=schema/Oauth2Config.yml
//go:generate apbr generate --platform=golang --path=./model/ --package=model --source-file=schema/Oauth2Provider.yml
//go:generate apbr generate --platform=golang --path=./model/ --package=model --source-file=schema/Oauth2Request.yml
//go:generate apbr generate --platform=golang --path=./model/ --package=model --source-file=schema/Oauth2Authenticate.yml
