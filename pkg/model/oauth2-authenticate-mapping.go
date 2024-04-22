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

type Oauth2AuthenticateMapper struct {
}

func NewOauth2AuthenticateMapper() *Oauth2AuthenticateMapper {
	return &Oauth2AuthenticateMapper{}
}

var Oauth2AuthenticateMapperInstance = NewOauth2AuthenticateMapper()

func (m *Oauth2AuthenticateMapper) New() *Oauth2Authenticate {
	return &Oauth2Authenticate{}
}

func (m *Oauth2AuthenticateMapper) ResourceIdentity() abs.ResourceIdentity {
	return abs.ResourceIdentity{
		Namespace: "sso",
		Name:      "Oauth2Authenticate",
	}
}

func (m *Oauth2AuthenticateMapper) ToRecord(oauth2Authenticate *Oauth2Authenticate) *model.Record {
	var rec = &model.Record{}
	rec.Properties = m.ToProperties(oauth2Authenticate)
	return rec
}

func (m *Oauth2AuthenticateMapper) FromRecord(record *model.Record) *Oauth2Authenticate {
	return m.FromProperties(record.Properties)
}

func (m *Oauth2AuthenticateMapper) ToProperties(oauth2Authenticate *Oauth2Authenticate) map[string]*structpb.Value {
	var properties = make(map[string]*structpb.Value)

	var_Id := oauth2Authenticate.Id

	if var_Id != nil {
		var var_Id_mapped *structpb.Value

		var var_Id_err error
		var_Id_mapped, var_Id_err = types.ByResourcePropertyType(model.ResourceProperty_UUID).Pack(*var_Id)
		if var_Id_err != nil {
			panic(var_Id_err)
		}
		properties["id"] = var_Id_mapped
	}

	var_Config := oauth2Authenticate.Config

	if var_Config != nil {
		var var_Config_mapped *structpb.Value

		var_Config_mapped = structpb.NewStructValue(&structpb.Struct{Fields: Oauth2ConfigMapperInstance.ToProperties(var_Config)})
		properties["config"] = var_Config_mapped
	}

	var_Code := oauth2Authenticate.Code

	var var_Code_mapped *structpb.Value

	var var_Code_err error
	var_Code_mapped, var_Code_err = types.ByResourcePropertyType(model.ResourceProperty_STRING).Pack(var_Code)
	if var_Code_err != nil {
		panic(var_Code_err)
	}
	properties["code"] = var_Code_mapped

	var_Version := oauth2Authenticate.Version

	var var_Version_mapped *structpb.Value

	var var_Version_err error
	var_Version_mapped, var_Version_err = types.ByResourcePropertyType(model.ResourceProperty_INT32).Pack(var_Version)
	if var_Version_err != nil {
		panic(var_Version_err)
	}
	properties["version"] = var_Version_mapped
	return properties
}

func (m *Oauth2AuthenticateMapper) FromProperties(properties map[string]*structpb.Value) *Oauth2Authenticate {
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
	if properties["config"] != nil && properties["config"].AsInterface() != nil {

		var_Config := properties["config"]
		var_Config_mapped := Oauth2ConfigMapperInstance.FromProperties(var_Config.GetStructValue().Fields)

		s.Config = var_Config_mapped
	}
	if properties["code"] != nil && properties["code"].AsInterface() != nil {

		var_Code := properties["code"]
		val, err := types.ByResourcePropertyType(model.ResourceProperty_STRING).UnPack(var_Code)

		if err != nil {
			panic(err)
		}

		var_Code_mapped := val.(string)

		s.Code = var_Code_mapped
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

func (m *Oauth2AuthenticateMapper) ToUnstructured(oauth2Authenticate *Oauth2Authenticate) unstructured.Unstructured {
	var properties unstructured.Unstructured = make(unstructured.Unstructured)
	properties["type"] = "sso/Oauth2Authenticate"

	var_Id := oauth2Authenticate.Id

	if var_Id != nil {
		var var_Id_mapped interface{}

		var_Id_mapped = var_Id.String()
		properties["id"] = var_Id_mapped
	}

	var_Config := oauth2Authenticate.Config

	if var_Config != nil {
		var var_Config_mapped interface{}

		var_Config_mapped = Oauth2ConfigMapperInstance.ToUnstructured(var_Config)
		properties["config"] = var_Config_mapped
	}

	var_Code := oauth2Authenticate.Code

	var var_Code_mapped interface{}

	var_Code_mapped = var_Code
	properties["code"] = var_Code_mapped

	var_Version := oauth2Authenticate.Version

	var var_Version_mapped interface{}

	var_Version_mapped = var_Version
	properties["version"] = var_Version_mapped

	return properties
}
