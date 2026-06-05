package aap

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// validScopes are the OAuth2 scopes AAP accepts for a token.
var validScopes = map[string]bool{
	"read":  true,
	"write": true,
}

// aapRoleEntry is an issuance policy: every token minted through creds/<name>
// inherits this role's scope, description, and lease TTLs.
type aapRoleEntry struct {
	Scope       string        `json:"scope"`
	Description string        `json:"description"`
	TTL         time.Duration `json:"ttl"`
	MaxTTL      time.Duration `json:"max_ttl"`
}

// toResponseData renders a role for the read/list API.
func (r *aapRoleEntry) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"scope":       r.Scope,
		"description": r.Description,
		"ttl":         int64(r.TTL.Seconds()),
		"max_ttl":     int64(r.MaxTTL.Seconds()),
	}
}

// pathRole defines the role/<name> and role/ (list) paths.
func pathRole(b *aapBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixAAP,
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role.",
					Required:    true,
				},
				"scope": {
					Type:        framework.TypeString,
					Default:     "read",
					Description: "OAuth2 scope granted to minted tokens: 'read' or 'write'. Defaults to least-privilege 'read'.",
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Description applied to minted AAP tokens (helps identify them in AAP).",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease TTL for tokens minted with this role.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease TTL for tokens minted with this role.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "role/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefixAAP,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *aapBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *aapBackend) pathRolesList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	// Storage does not guarantee order; sort for a stable API response.
	sort.Strings(entries)
	return logical.ListResponse(entries), nil
}

func (b *aapBackend) pathRolesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return &logical.Response{Data: entry.toResponseData()}, nil
}

func (b *aapBackend) pathRolesWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, ok := data.GetOk("name")
	if !ok {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name.(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = new(aapRoleEntry)
	}

	createOperation := req.Operation == logical.CreateOperation

	if scope, ok := data.GetOk("scope"); ok {
		role.Scope = scope.(string)
	} else if createOperation {
		role.Scope = data.Get("scope").(string) // apply default
	}
	if !validScopes[role.Scope] {
		return logical.ErrorResponse("invalid scope %q: must be 'read' or 'write'", role.Scope), nil
	}

	if description, ok := data.GetOk("description"); ok {
		role.Description = description.(string)
	}

	if ttlRaw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}
	if maxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if role.MaxTTL != 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl (%s) cannot exceed max_ttl (%s)", role.TTL, role.MaxTTL), nil
	}

	if err := b.setRole(ctx, req.Storage, name.(string), role); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *aapBackend) pathRolesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "role/"+data.Get("name").(string)); err != nil {
		return nil, fmt.Errorf("error deleting AAP role: %w", err)
	}
	return nil, nil
}

// getRole loads a role by name, returning nil if it does not exist.
func (b *aapBackend) getRole(ctx context.Context, s logical.Storage, name string) (*aapRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, "role/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role aapRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// setRole persists a role.
func (b *aapBackend) setRole(ctx context.Context, s logical.Storage, name string, role *aapRoleEntry) error {
	entry, err := logical.StorageEntryJSON("role/"+name, role)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}
	return s.Put(ctx, entry)
}

const (
	pathRoleHelpSynopsis        = "Manage AAP token issuance roles."
	pathRoleHelpDescription     = "Define the scope, description, and lease TTLs applied to AAP tokens minted through this role."
	pathRoleListHelpSynopsis    = "List configured AAP token roles."
	pathRoleListHelpDescription = "List the names of all roles configured on this AAP secrets engine."
)
