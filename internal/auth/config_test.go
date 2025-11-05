// nolint: funlen
package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParamConfig_Key(t *testing.T) {
	tests := []struct {
		name string
		p    ParamConfig
		want string
	}{
		{
			name: "uses name when expr empty",
			p:    ParamConfig{Name: "X-Request-Id"},
			want: "X-Request-Id",
		},
		{
			name: "uses expr when present",
			p:    ParamConfig{Name: "ignored", Expr: "claims.sub"},
			want: "claims.sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.p.Key())
		})
	}
}

func TestRuleConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		r       RuleConfig
		wantErr string
	}{
		{
			name: "happy path with Format and matching ParamNames",
			r: RuleConfig{
				Format:     "%s-%s",
				ParamNames: []string{"a", "b"},
			},
		},
		{
			name: "happy path with single Case",
			r: RuleConfig{
				Cases: []RuleCase{
					{
						When:       "x == 'y'",
						Format:     "%s",
						ParamNames: []string{"id"},
					},
				},
			},
		},
		{
			name: "error when Format empty and no Cases",
			r: RuleConfig{
				Format:     "",
				ParamNames: []string{"a"},
			},
			wantErr: "Format is required when cases is empty",
		},
		{
			name: "error when %s count mismatches ParamNames (no cases)",
			r: RuleConfig{
				Format:     "%s-%s",
				ParamNames: []string{"onlyOne"},
			},
			wantErr: "Format %s count (2) must equal ParamNames length (1)",
		},
		{
			name: "error when Cases present but Format not empty",
			r: RuleConfig{
				Format:     "%s",
				ParamNames: nil,
				Cases: []RuleCase{
					{Format: "%s", ParamNames: []string{"id"}},
				},
			},
			wantErr: "Format must be empty when cases are present",
		},
		{
			name: "error when Cases present but ParamNames not empty on parent",
			r: RuleConfig{
				ParamNames: []string{"shouldBeEmpty"},
				Cases: []RuleCase{
					{Format: "%s", ParamNames: []string{"id"}},
				},
			},
			wantErr: "ParamNames must be empty when cases are present",
		},
		{
			name: "error when a Case has empty when",
			r: RuleConfig{
				Cases: []RuleCase{
					{Format: "%s", When: "", ParamNames: []string{"id"}},
				},
			},
			wantErr: "cases[0].when is required",
		},
		{
			name: "error when a Case has empty format",
			r: RuleConfig{
				Cases: []RuleCase{
					{Format: "", When: "true", ParamNames: []string{"id"}},
				},
			},
			wantErr: "cases[0].format is required",
		},
		{
			name: "error when Case %s count mismatches",
			r: RuleConfig{
				Cases: []RuleCase{
					{Format: "%s-%s", When: "true", ParamNames: []string{"onlyOne"}},
				},
			},
			wantErr: "cases[0].format %s count (2) must equal ParamNames length (1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Validate()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRouteConfig_Validate(t *testing.T) {
	route := func(method string, params []ParamConfig, rules []RuleConfig) Route {
		return Route{
			HttpMethod:    method,
			RelativePaths: []string{"/ok"},
			Params:        params,
			Rules:         rules,
		}
	}
	rc := func(routes ...Route) *RouteConfig {
		return &RouteConfig{Routes: routes}
	}

	t.Run("happy path minimal - RelativePaths", func(t *testing.T) {
		cfg := rc(route("GET", nil, nil))
		require.NoError(t, cfg.Validate())
	})

	t.Run("happy path minimal - RelativePath", func(t *testing.T) {
		r := Route{
			HttpMethod:   "GET",
			RelativePath: "/ok",
		}
		cfg := rc(r)
		require.NoError(t, cfg.Validate())
	})

	t.Run("happy path minimal - HttpMethods", func(t *testing.T) {
		r := Route{
			HttpMethods:  []string{"GET"},
			RelativePath: "/ok",
		}
		cfg := rc(r)
		require.NoError(t, cfg.Validate())
	})

	t.Run("happy path minimal - bad HttpMethods", func(t *testing.T) {
		r := Route{
			HttpMethods:  []string{"GET", "BAD"},
			RelativePath: "/ok",
		}
		cfg := rc(r)
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Routes[0].HttpMethods[1]: must be one of [GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE ANY]; got BAD")
	})

	t.Run("invalid http method -> oneof error surfaced", func(t *testing.T) {
		cfg := rc(route("FETCH", nil, nil))
		err := cfg.Validate()
		require.Error(t, err)
		msg := err.Error()
		assert.Contains(t, msg, "Routes[0].HttpMethod: must be one of")
		assert.Contains(t, msg, "FETCH")
	})

	t.Run("unknown param function -> clear error from describeValidationErrors", func(t *testing.T) {
		cfg := rc(route("GET", []ParamConfig{
			{
				Name:     "x",
				Source:   ParamSourceQuery,
				Function: "notAFunction",
			},
		}, nil))
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Params[0].Function: unknown function notAFunction")
	})

	t.Run("dive error propagates for invalid rules via RuleConfig.Validate", func(t *testing.T) {
		badRule := RuleConfig{
			Format:     "",
			ParamNames: []string{"id"},
		}
		cfg := rc(route("GET", nil, []RuleConfig{badRule}))
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "routes[0].rules[0]: rule validation: Format is required when cases is empty")
	})

	t.Run("multiple aggregated validation lines", func(t *testing.T) {
		cfg := &RouteConfig{
			Routes: []Route{
				{
					HttpMethod: "BAD", // oneof failure
					Params: []ParamConfig{
						// Missing required Source -> "required"
						{Name: "p"},
						// Unknown function -> param_function
						{Name: "q", Source: ParamSourceHeader, Function: "nope"},
					},
				},
			},
		}
		err := cfg.Validate()
		require.Error(t, err)
		msg := err.Error()

		// Ensure multiple problems are joined with " | "
		assert.Contains(t, msg, " | ")

		// Spot-check a few transformed messages
		assert.Contains(t, msg, "Routes[0].HttpMethod: must be one of")
		assert.Contains(t, msg, "Routes[0].Params[0].Source: is required")
		assert.Contains(t, msg, "Routes[0].Params[1].Function: unknown function nope")
	})
}

func TestDescribeValidationErrors_FallsBackOnNonValidationError(t *testing.T) {
	e := describeValidationErrors(assert.AnError)
	assert.Equal(t, assert.AnError.Error(), e)
}

func TestRuleConfig_Validate_AllErrorsTogether(t *testing.T) {
	r := RuleConfig{
		Format:     "%s",                 // should be empty because Cases present
		ParamNames: []string{"shouldnt"}, // must be empty when Cases present
		Cases: []RuleCase{
			{Format: "%s-%s", When: "true", ParamNames: []string{"onlyOne"}}, // mismatch inside case
		},
	}
	err := r.Validate()
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "Format must be empty when cases are present")
	assert.Contains(t, msg, "ParamNames must be empty when cases are present")
	assert.Contains(t, msg, "cases[0].format %s count (2) must equal ParamNames length (1)")
}

func TestRouteConfig_Validate_RuleErrorIsWrappedWithIndices(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{HttpMethod: "GET", RelativePath: "/user/:id"},
			{
				HttpMethod:   "POST",
				RelativePath: "/user/:id",
				Rules: []RuleConfig{
					{ // ok
						Format:     "%s",
						ParamNames: []string{"id"},
					},
					{ // bad
						Format:     "",
						ParamNames: []string{"x"},
					},
				},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "routes[1].rules[1]: rule validation: Format is required when cases is empty")
}

func TestDescribeValidationErrors_OneOfFormatting(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "WRONG",
				Params:     []ParamConfig{qp("a"), hp("b")},
			},
		},
	}
	err := cfg.Validate()
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "must be one of")
	assert.Contains(t, msg, "WRONG")
}

func TestParamFunctionTag_ChecksAgainstBuiltinCaseInsensitively(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "GET", RelativePath: "/user/:id",
				Params: []ParamConfig{
					{Name: "x", Source: ParamSourceQuery, Function: "B64DEC"},
				},
			},
		},
	}
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestRouteConfig_Validate_RulesPassThrough(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "PUT", RelativePath: "/user/:id",
				Rules: []RuleConfig{
					{Format: "%s-%s", ParamNames: []string{"a", "b"}},
				},
			},
		},
	}
	require.NoError(t, cfg.Validate())
}

func TestRouteConfig_Validate_ParamsAndRulesTogether(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "DELETE", RelativePath: "/user/:id",
				Params: []ParamConfig{
					{Name: "Host", Source: ParamSourceHeader},
				},
				Rules: []RuleConfig{
					{Format: "%s", ParamNames: []string{"Host"}},
				},
			},
		},
	}
	require.NoError(t, cfg.Validate())
}

func TestRouteConfig_Validate_ParamRegex_EmptyPattern(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "GET", RelativePaths: []string{"/user/:id"},
				Params: []ParamConfig{
					{
						Name:     "projectId",
						Source:   ParamSourceURLPath,
						Function: "regex",
						Expr:     "", // <-- empty pattern should error
					},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	msg := err.Error()

	assert.Contains(t, msg, "routes[0].params[0]:")
	assert.Contains(t, msg, "regex pattern (Expr) is empty")
	assert.Contains(t, msg, "projectId")
}

func TestRouteConfig_Validate_ParamRegex_InvalidPattern(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "POST", RelativePath: "/user/:id",
				Params: []ParamConfig{
					{
						Name:     "subscriptionId",
						Source:   ParamSourceURLPath,
						Function: "regex",
						Expr:     `([unclosed`, // <-- invalid regex
					},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	msg := err.Error()

	assert.Contains(t, msg, "routes[0].params[0]:")
	assert.Contains(t, msg, "invalid regex")
	assert.Contains(t, msg, "([unclosed")
}

func TestRouteConfig_Validate_ParamRegex_HappyPath(t *testing.T) {
	cfg := &RouteConfig{
		Routes: []Route{
			{
				HttpMethod: "GET", RelativePath: "/user/:id",
				Params: []ParamConfig{
					{
						Name:     "projectId",
						Source:   ParamSourceURLPath,
						Function: "regex",
						Expr:     `^/v1/projects/([^/]+)/topics/[^/]+$`, // valid pattern
					},
				},
				Rules: []RuleConfig{
					{Format: "%s", ParamNames: []string{"projectId"}},
				},
			},
		},
	}

	require.NoError(t, cfg.Validate())
}

func qp(name string) ParamConfig {
	return ParamConfig{
		Name:   name,
		Source: ParamSourceQuery,
	}
}

func hp(name string) ParamConfig {
	return ParamConfig{
		Name:   name,
		Source: ParamSourceHeader,
	}
}
