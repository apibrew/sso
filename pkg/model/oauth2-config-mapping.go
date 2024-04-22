// Code generated by apbr generate. DO NOT EDIT.
// versions:
// 	apbr generate v1.2

//go:build !codeanalysis

package model

import (
	"github.com/apibrew/apibrew/pkg/abs"
	"github.com/apibrew/apibrew/pkg/formats/unstructured"
	"github.com/apibrew/apibrew/pkg/model"
	"github.com/apibrew/apibrew/pkg/types"
	"google.golang.org/protobuf/types/known/structpb"
)

import "github.com/google/uuid"

type Oauth2ConfigMapper struct {
}

func NewOauth2ConfigMapper() *Oauth2ConfigMapper {
	return &Oauth2ConfigMapper{}
}

var Oauth2ConfigMapperInstance = NewOauth2ConfigMapper()

func (m *Oauth2ConfigMapper) New() *Oauth2Config {
	return &Oauth2Config{}
}

func (m *Oauth2ConfigMapper) ResourceIdentity() abs.ResourceIdentity {
	return abs.ResourceIdentity{
		Namespace: "sso",
		Name:      "Oauth2Config",
	}
}

func (m *Oauth2ConfigMapper) ToRecord(oauth2Config *Oauth2Config) *model.Record {
	var rec = &model.Record{}
	rec.Properties = m.ToProperties(oauth2Config)
	return rec
}

func (m *Oauth2ConfigMapper) FromRecord(record *model.Record) *Oauth2Config {
	return m.FromProperties(record.Properties)
}

func (m *Oauth2ConfigMapper) ToProperties(oauth2Config *Oauth2Config) map[string]*structpb.Value {
	var properties = make(map[string]*structpb.Value)

	var_Id := oauth2Config.Id

	if var_Id != nil {
		var var_Id_mapped *structpb.Value

		var var_Id_err error
		var_Id_mapped, var_Id_err = types.ByResourcePropertyType(model.ResourceProperty_UUID).Pack(*var_Id)
		if var_Id_err != nil {
			panic(var_Id_err)
		}
		properties["id"] = var_Id_mapped
	}

	var_Scopes := oauth2Config.Scopes

	if var_Scopes != nil {
		var var_Scopes_mapped *structpb.Value

		var var_Scopes_l []*structpb.Value
		for _, value := range var_Scopes {

			var_5x := value
			var var_5x_mapped *structpb.Value

			var var_5x_err error
			var_5x_mapped, var_5x_err = types.ByResourcePropertyType(model.ResourceProperty_STRING).Pack(var_5x)
			if var_5x_err != nil {
				panic(var_5x_err)
			}

			var_Scopes_l = append(var_Scopes_l, var_5x_mapped)
		}
		var_Scopes_mapped = structpb.NewListValue(&structpb.ListValue{Values: var_Scopes_l})
		properties["scopes"] = var_Scopes_mapped
	}

	var_NewUserRoles := oauth2Config.NewUserRoles

	if var_NewUserRoles != nil {
		var var_NewUserRoles_mapped *structpb.Value

		var var_NewUserRoles_l []*structpb.Value
		for _, value := range var_NewUserRoles {

			var_5x := value
			var var_5x_mapped *structpb.Value

			var var_5x_err error
			var_5x_mapped, var_5x_err = types.ByResourcePropertyType(model.ResourceProperty_STRING).Pack(var_5x)
			if var_5x_err != nil {
				panic(var_5x_err)
			}

			var_NewUserRoles_l = append(var_NewUserRoles_l, var_5x_mapped)
		}
		var_NewUserRoles_mapped = structpb.NewListValue(&structpb.ListValue{Values: var_NewUserRoles_l})
		properties["newUserRoles"] = var_NewUserRoles_mapped
	}

	var_Name := oauth2Config.Name

	var var_Name_mapped *structpb.Value

	var var_Name_err error
	var_Name_mapped, var_Name_err = types.ByResourcePropertyType(model.ResourceProperty_STRING).Pack(var_Name)
	if var_Name_err != nil {
		panic(var_Name_err)
	}
	properties["name"] = var_Name_mapped

	var_Provider := oauth2Config.Provider

	if var_Provider != nil {
		var var_Provider_mapped *structpb.Value

		var_Provider_mapped = structpb.NewStructValue(&structpb.Struct{Fields: Oauth2ProviderMapperInstance.ToProperties(var_Provider)})
		properties["provider"] = var_Provider_mapped
	}

	var_ClientId := oauth2Config.ClientId

	var var_ClientId_mapped *structpb.Value

	var var_ClientId_err error
	var_ClientId_mapped, var_ClientId_err = types.ByResourcePropertyType(model.ResourceProperty_STRING).Pack(var_ClientId)
	if var_ClientId_err != nil {
		panic(var_ClientId_err)
	}
	properties["clientId"] = var_ClientId_mapped

	var_ClientSecret := oauth2Config.ClientSecret

	var var_ClientSecret_mapped *structpb.Value

	var var_ClientSecret_err error
	var_ClientSecret_mapped, var_ClientSecret_err = types.ByResourcePropertyType(model.ResourceProperty_STRING).Pack(var_ClientSecret)
	if var_ClientSecret_err != nil {
		panic(var_ClientSecret_err)
	}
	properties["clientSecret"] = var_ClientSecret_mapped

	var_Version := oauth2Config.Version

	var var_Version_mapped *structpb.Value

	var var_Version_err error
	var_Version_mapped, var_Version_err = types.ByResourcePropertyType(model.ResourceProperty_INT32).Pack(var_Version)
	if var_Version_err != nil {
		panic(var_Version_err)
	}
	properties["version"] = var_Version_mapped
	return properties
}

func (m *Oauth2ConfigMapper) FromProperties(properties map[string]*structpb.Value) *Oauth2Config {
	var s = m.New()
	if properties["id"] != nil && properties["id"].AsInterface() != nil {

		var_Id := properties["id"]
		val, err := types.ByResourcePropertyType(model.ResourceProperty_UUID).UnPack(var_Id)

		if err != nil {
			panic(err)
		}

		var_Id_mapped := new(uuid.UUID)
		*var_Id_mapped = val.(uuid.UUID)

		s.Id = var_Id_mapped
	}
	if properties["scopes"] != nil && properties["scopes"].AsInterface() != nil {

		var_Scopes := properties["scopes"]
		var_Scopes_mapped := []string{}
		for _, v := range var_Scopes.GetListValue().Values {

			var_4x := v
			val, err := types.ByResourcePropertyType(model.ResourceProperty_STRING).UnPack(var_4x)

			if err != nil {
				panic(err)
			}

			var_4x_mapped := val.(string)

			var_Scopes_mapped = append(var_Scopes_mapped, var_4x_mapped)
		}

		s.Scopes = var_Scopes_mapped
	}
	if properties["newUserRoles"] != nil && properties["newUserRoles"].AsInterface() != nil {

		var_NewUserRoles := properties["newUserRoles"]
		var_NewUserRoles_mapped := []string{}
		for _, v := range var_NewUserRoles.GetListValue().Values {

			var_4x := v
			val, err := types.ByResourcePropertyType(model.ResourceProperty_STRING).UnPack(var_4x)

			if err != nil {
				panic(err)
			}

			var_4x_mapped := val.(string)

			var_NewUserRoles_mapped = append(var_NewUserRoles_mapped, var_4x_mapped)
		}

		s.NewUserRoles = var_NewUserRoles_mapped
	}
	if properties["name"] != nil && properties["name"].AsInterface() != nil {

		var_Name := properties["name"]
		val, err := types.ByResourcePropertyType(model.ResourceProperty_STRING).UnPack(var_Name)

		if err != nil {
			panic(err)
		}

		var_Name_mapped := val.(string)

		s.Name = var_Name_mapped
	}
	if properties["provider"] != nil && properties["provider"].AsInterface() != nil {

		var_Provider := properties["provider"]
		var_Provider_mapped := Oauth2ProviderMapperInstance.FromProperties(var_Provider.GetStructValue().Fields)

		s.Provider = var_Provider_mapped
	}
	if properties["clientId"] != nil && properties["clientId"].AsInterface() != nil {

		var_ClientId := properties["clientId"]
		val, err := types.ByResourcePropertyType(model.ResourceProperty_STRING).UnPack(var_ClientId)

		if err != nil {
			panic(err)
		}

		var_ClientId_mapped := val.(string)

		s.ClientId = var_ClientId_mapped
	}
	if properties["clientSecret"] != nil && properties["clientSecret"].AsInterface() != nil {

		var_ClientSecret := properties["clientSecret"]
		val, err := types.ByResourcePropertyType(model.ResourceProperty_STRING).UnPack(var_ClientSecret)

		if err != nil {
			panic(err)
		}

		var_ClientSecret_mapped := val.(string)

		s.ClientSecret = var_ClientSecret_mapped
	}
	if properties["version"] != nil && properties["version"].AsInterface() != nil {

		var_Version := properties["version"]
		val, err := types.ByResourcePropertyType(model.ResourceProperty_INT32).UnPack(var_Version)

		if err != nil {
			panic(err)
		}

		var_Version_mapped := val.(int32)

		s.Version = var_Version_mapped
	}
	return s
}

func (m *Oauth2ConfigMapper) ToUnstructured(oauth2Config *Oauth2Config) unstructured.Unstructured {
	var properties unstructured.Unstructured = make(unstructured.Unstructured)
	properties["type"] = "sso/Oauth2Config"

	var_Id := oauth2Config.Id

	if var_Id != nil {
		var var_Id_mapped interface{}

		var_Id_mapped = var_Id.String()
		properties["id"] = var_Id_mapped
	}

	var_Scopes := oauth2Config.Scopes

	if var_Scopes != nil {
		var var_Scopes_mapped interface{}

		var var_Scopes_l []interface{}
		for _, value := range var_Scopes {

			var_5x := value
			var var_5x_mapped interface{}

			var_5x_mapped = var_5x

			var_Scopes_l = append(var_Scopes_l, var_5x_mapped)
		}
		var_Scopes_mapped = var_Scopes_l
		properties["scopes"] = var_Scopes_mapped
	}

	var_NewUserRoles := oauth2Config.NewUserRoles

	if var_NewUserRoles != nil {
		var var_NewUserRoles_mapped interface{}

		var var_NewUserRoles_l []interface{}
		for _, value := range var_NewUserRoles {

			var_5x := value
			var var_5x_mapped interface{}

			var_5x_mapped = var_5x

			var_NewUserRoles_l = append(var_NewUserRoles_l, var_5x_mapped)
		}
		var_NewUserRoles_mapped = var_NewUserRoles_l
		properties["newUserRoles"] = var_NewUserRoles_mapped
	}

	var_Name := oauth2Config.Name

	var var_Name_mapped interface{}

	var_Name_mapped = var_Name
	properties["name"] = var_Name_mapped

	var_Provider := oauth2Config.Provider

	if var_Provider != nil {
		var var_Provider_mapped interface{}

		var_Provider_mapped = Oauth2ProviderMapperInstance.ToUnstructured(var_Provider)
		properties["provider"] = var_Provider_mapped
	}

	var_ClientId := oauth2Config.ClientId

	var var_ClientId_mapped interface{}

	var_ClientId_mapped = var_ClientId
	properties["clientId"] = var_ClientId_mapped

	var_ClientSecret := oauth2Config.ClientSecret

	var var_ClientSecret_mapped interface{}

	var_ClientSecret_mapped = var_ClientSecret
	properties["clientSecret"] = var_ClientSecret_mapped

	var_Version := oauth2Config.Version

	var var_Version_mapped interface{}

	var_Version_mapped = var_Version
	properties["version"] = var_Version_mapped

	return properties
}
