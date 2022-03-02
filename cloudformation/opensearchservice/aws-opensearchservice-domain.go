package opensearchservice

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/awslabs/goformation/v4/cloudformation/policies"
	"github.com/awslabs/goformation/v4/cloudformation/tags"
)

// Domain_MasterUserOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.MasterUserOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-masteruseroptions.html
type Domain_MasterUserOptions struct {
	MasterUserARN      string `json:"MasterUserARN,omitempty"`
	MasterUserName     string `json:"MasterUserName,omitempty"`
	MasterUserPassword string `json:"MasterUserPassword,omitempty"`
}

func (r *Domain_MasterUserOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.MasterUserOptions"
}

// Domain_AdvancedSecurityOptionsInput AWS CloudFormation Resource (AWS::OpenSearchService::Domain.AdvancedSecurityOptionsInput)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-advancedsecurityoptionsinput.html
type Domain_AdvancedSecurityOptionsInput struct {
	Enabled                     bool                      `json:"Enabled,omitempty"`
	InternalUserDatabaseEnabled bool                      `json:"InternalUserDatabaseEnabled,omitempty"`
	MasterUserOptions           *Domain_MasterUserOptions `json:"MasterUserOptions,omitempty"`
}

func (r *Domain_AdvancedSecurityOptionsInput) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.AdvancedSecurityOptionsInput"
}

// Domain_CognitoOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.CognitoOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-cognitooptions.html
type Domain_CognitoOptions struct {
	Enabled        bool   `json:"Enabled,omitempty"`
	IdentityPoolId string `json:"IdentityPoolId,omitempty"`
	RoleArn        string `json:"RoleArn,omitempty"`
	UserPoolId     string `json:"UserPoolId,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_CognitoOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.CognitoOptions"
}

// Domain_DomainEndpointOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.DomainEndpointOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-domainendpointoptions.html
type Domain_DomainEndpointOptions struct {
	CustomEndpoint               string `json:"CustomEndpoint,omitempty"`
	CustomEndpointCertificateArn string `json:"CustomEndpointCertificateArn,omitempty"`
	CustomEndpointEnabled        bool   `json:"CustomEndpointEnabled,omitempty"`
	EnforceHTTPS                 bool   `json:"EnforceHTTPS,omitempty"`
	TLSSecurityPolicy            string `json:"TLSSecurityPolicy,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_DomainEndpointOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.DomainEndpointOptions"
}

// Domain_NodeToNodeEncryptionOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.NodeToNodeEncryptionOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-nodetonodeencryptionoptions.html
type Domain_NodeToNodeEncryptionOptions struct {
	Enabled bool `json:"Enabled,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_NodeToNodeEncryptionOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.NodeToNodeEncryptionOptions"
}

// Domain_EBSOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.EBSOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-ebsoptions.html
type Domain_EBSOptions struct {
	EBSEnabled bool   `json:"EBSEnabled,omitempty"`
	Iops       int    `json:"Iops,omitempty"`
	VolumeSize int    `json:"VolumeSize,omitempty"`
	VolumeType string `json:"VolumeType,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_EBSOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.EBSOptions"
}

// Domain_SnapshotOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.SnapshotOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-snapshotoptions.html
type Domain_SnapshotOptions struct {
	AutomatedSnapshotStartHour int `json:"AutomatedSnapshotStartHour,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_SnapshotOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.SnapshotOptions"
}

// Domain_VPCOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.VPCOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-vpcoptions.html
type Domain_VPCOptions struct {
	SecurityGroupIds []string `json:"SecurityGroupIds,omitempty"`
	SubnetIds        []string `json:"SubnetIds,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_VPCOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.VPCOptions"
}

// Domain_ZoneAwarenessConfig AWS CloudFormation Resource (AWS::OpenSearchService::Domain.ZoneAwarenessConfig)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-zoneawarenessconfig.html
type Domain_ZoneAwarenessConfig struct {
	AvailabilityZoneCount int `json:"AvailabilityZoneCount,omitempty"`
}

func (r *Domain_ZoneAwarenessConfig) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.ZoneAwarenessConfig"
}

// Domain_ClusterConfig AWS CloudFormation Resource (AWS::OpenSearchService::Domain.ClusterConfig)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-clusterconfig.html
type Domain_ClusterConfig struct {
	DedicatedMasterCount   int                         `json:"DedicatedMasterCount,omitempty"`
	DedicatedMasterEnabled bool                        `json:"DedicatedMasterEnabled,omitempty"`
	DedicatedMasterType    string                      `json:"DedicatedMasterType,omitempty"`
	InstanceCount          int                         `json:"InstanceCount,omitempty"`
	InstanceType           string                      `json:"InstanceType,omitempty"`
	WarmCount              int                         `json:"WarmCount,omitempty"`
	WarmEnabled            bool                        `json:"WarmEnabled,omitempty"`
	WarmType               string                      `json:"WarmType,omitempty"`
	ZoneAwarenessConfig    *Domain_ZoneAwarenessConfig `json:"ZoneAwarenessConfig,omitempty"`
	ZoneAwarenessEnabled   bool                        `json:"ZoneAwarenessEnabled,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_ClusterConfig) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.ClusterConfig"
}

// Domain_EncryptionAtRestOptions AWS CloudFormation Resource (AWS::OpenSearchService::Domain.EncryptionAtRestOptions)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-encryptionatrestoptions.html
type Domain_EncryptionAtRestOptions struct {
	Enabled  bool   `json:"Enabled,omitempty"`
	KmsKeyId string `json:"KmsKeyId,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_EncryptionAtRestOptions) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.EncryptionAtRestOptions"
}

// Domain_LogPublishingOption AWS CloudFormation Resource (AWS::OpenSearchService::Domain.LogPublishingOption)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-opensearchservice-domain-logpublishingoption.html
type Domain_LogPublishingOption struct {
	CloudWatchLogsLogGroupArn string `json:"CloudWatchLogsLogGroupArn,omitempty"`
	Enabled                   bool   `json:"Enabled,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain_LogPublishingOption) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain.LogPublishingOption"
}

// Domain AWS CloudFormation Resource (AWS::OpenSearchService::Domain)
// See: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html
type Domain struct {
	AccessPolicies              interface{}                           `json:"AccessPolicies,omitempty"`
	AdvancedOptions             map[string]string                     `json:"AdvancedOptions,omitempty"`
	AdvancedSecurityOptions     *Domain_AdvancedSecurityOptionsInput  `json:"AdvancedSecurityOptions,omitempty"`
	ClusterConfig               *Domain_ClusterConfig                 `json:"ClusterConfig,omitempty"`
	CognitoOptions              *Domain_CognitoOptions                `json:"CognitoOptions,omitempty"`
	DomainEndpointOptions       *Domain_DomainEndpointOptions         `json:"DomainEndpointOptions,omitempty"`
	DomainName                  string                                `json:"DomainName,omitempty"`
	EBSOptions                  *Domain_EBSOptions                    `json:"EBSOptions,omitempty"`
	EncryptionAtRestOptions     *Domain_EncryptionAtRestOptions       `json:"EncryptionAtRestOptions,omitempty"`
	EngineVersion               string                                `json:"EngineVersion,omitempty"`
	LogPublishingOptions        map[string]Domain_LogPublishingOption `json:"LogPublishingOptions,omitempty"`
	NodeToNodeEncryptionOptions *Domain_NodeToNodeEncryptionOptions   `json:"NodeToNodeEncryptionOptions,omitempty"`
	SnapshotOptions             *Domain_SnapshotOptions               `json:"SnapshotOptions,omitempty"`
	Tags                        []tags.Tag                            `json:"Tags,omitempty"`
	VPCOptions                  *Domain_VPCOptions                    `json:"VPCOptions,omitempty"`

	AWSCloudFormationDeletionPolicy      policies.DeletionPolicy      `json:"-"`
	AWSCloudFormationUpdateReplacePolicy policies.UpdateReplacePolicy `json:"-"`
	AWSCloudFormationDependsOn           []string                     `json:"-"`
	AWSCloudFormationMetadata            map[string]interface{}       `json:"-"`
	AWSCloudFormationCondition           string                       `json:"-"`
}

func (r *Domain) AWSCloudFormationType() string {
	return "AWS::OpenSearchService::Domain"
}

// MarshalJSON is a custom JSON marshalling hook that embeds this object into
// an AWS CloudFormation JSON resource's 'Properties' field and adds a 'Type'.
func (r Domain) MarshalJSON() ([]byte, error) {
	type Properties Domain
	return json.Marshal(&struct {
		Type                string
		Properties          Properties
		DependsOn           []string                     `json:"DependsOn,omitempty"`
		Metadata            map[string]interface{}       `json:"Metadata,omitempty"`
		DeletionPolicy      policies.DeletionPolicy      `json:"DeletionPolicy,omitempty"`
		UpdateReplacePolicy policies.UpdateReplacePolicy `json:"UpdateReplacePolicy,omitempty"`
		Condition           string                       `json:"Condition,omitempty"`
	}{
		Type:                r.AWSCloudFormationType(),
		Properties:          (Properties)(r),
		DependsOn:           r.AWSCloudFormationDependsOn,
		Metadata:            r.AWSCloudFormationMetadata,
		DeletionPolicy:      r.AWSCloudFormationDeletionPolicy,
		UpdateReplacePolicy: r.AWSCloudFormationUpdateReplacePolicy,
		Condition:           r.AWSCloudFormationCondition,
	})
}

// UnmarshalJSON is a custom JSON unmarshalling hook that strips the outer
// AWS CloudFormation resource object, and just keeps the 'Properties' field.
func (r *Domain) UnmarshalJSON(b []byte) error {
	type Properties Domain
	res := &struct {
		Type                string
		Properties          *Properties
		DependsOn           []string
		Metadata            map[string]interface{}
		DeletionPolicy      string
		UpdateReplacePolicy string
		Condition           string
	}{}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // Force error if unknown field is found

	if err := dec.Decode(&res); err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return err
	}

	// If the resource has no Properties set, it could be nil
	if res.Properties != nil {
		*r = Domain(*res.Properties)
	}
	if res.DependsOn != nil {
		r.AWSCloudFormationDependsOn = res.DependsOn
	}
	if res.Metadata != nil {
		r.AWSCloudFormationMetadata = res.Metadata
	}
	if res.DeletionPolicy != "" {
		r.AWSCloudFormationDeletionPolicy = policies.DeletionPolicy(res.DeletionPolicy)
	}
	if res.UpdateReplacePolicy != "" {
		r.AWSCloudFormationUpdateReplacePolicy = policies.UpdateReplacePolicy(res.UpdateReplacePolicy)
	}
	if res.Condition != "" {
		r.AWSCloudFormationCondition = res.Condition
	}
	return nil
}
