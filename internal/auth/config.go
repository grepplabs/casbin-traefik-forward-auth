package auth

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-playground/validator/v10"
)

const (
	HttpMethodAny = "ANY"
)

type ParamSource string

const (
	ParamSourcePath          ParamSource = "path"
	ParamSourceQuery         ParamSource = "query"
	ParamSourceHeader        ParamSource = "header"
	ParamSourceClaim         ParamSource = "claim"
	ParamSourceBasicAuthUser ParamSource = "basicAuthUser"
	ParamSourceURL           ParamSource = "url"
	ParamSourceURLPath       ParamSource = "urlPath"
	ParamSourceHTTPMethod    ParamSource = "httpMethod"
)

type ParamConfig struct {
	Name     string      `json:"name" yaml:"name" binding:"required"` // param name (e.g. "x" or "X-Name")
	Source   ParamSource `json:"source" yaml:"source" binding:"required,oneof=path query header claim basicAuthUser url urlPath httpMethod"`
	Default  string      `json:"default,omitempty" yaml:"default,omitempty"`                                      // optional fallback if value is empty
	Function string      `json:"function,omitempty" yaml:"function,omitempty" binding:"omitempty,param_function"` // function
	Expr     string      `json:"expr,omitempty" yaml:"expr,omitempty"`                                            // expression
}

func (p *ParamConfig) Key() string {
	if len(p.Expr) != 0 {
		return p.Expr
	}
	return p.Name
}

type RuleConfig struct {
	Format     string   `json:"format,omitempty" yaml:"format,omitempty"`         // "%s-%s" -> "default" "%s"
	ParamNames []string `json:"paramNames,omitempty" yaml:"paramNames,omitempty"` // ["id", "q"]
	// conditionals
	Cases []RuleCase `json:"cases,omitempty" yaml:"cases,omitempty"`
}

type RuleCase struct {
	When       string   `json:"when,omitempty" yaml:"when,omitempty"`
	Format     string   `json:"format" yaml:"format"`
	ParamNames []string `json:"paramNames,omitempty" yaml:"paramNames,omitempty" binding:"dive,required"`
}
type Route struct {
	HttpMethod    string        `json:"httpMethod,omitempty" yaml:"httpMethod,omitempty" binding:"omitempty,oneof=GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE ANY"`
	HttpMethods   []string      `json:"httpMethods,omitempty" yaml:"httpMethods,omitempty" binding:"omitempty,min=1,dive,oneof=GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE ANY"`
	RelativePath  string        `json:"relativePath,omitempty" yaml:"relativePath,omitempty"`
	RelativePaths []string      `json:"relativePaths,omitempty" yaml:"relativePaths,omitempty"`  // e.g. "/user/:id"
	Params        []ParamConfig `json:"params,omitempty" yaml:"params,omitempty" binding:"dive"` // params to extract
	Rules         []RuleConfig  `json:"rules,omitempty" yaml:"rules,omitempty" binding:"dive"`   // cabin arguments (if missing -> use params)
}

func (rc *Route) Validate() error {
	return nil
}

type RouteConfig struct {
	Routes []Route `json:"routes" yaml:"routes" binding:"dive,required"`
}

// nolint:cyclop
func (rc *RouteConfig) Validate() error {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.SetTagName("binding")
	err := v.RegisterValidation("param_function", func(fl validator.FieldLevel) bool {
		name := strings.ToLower(strings.TrimSpace(fl.Field().String()))
		if name == "" {
			return true
		}
		_, ok := builtinFunc[name]
		return ok
	})
	if err != nil {
		return err
	}
	err = v.Struct(rc)
	if err != nil {
		return fmt.Errorf("validation error: %s", describeValidationErrors(err))
	}
	for ri := range rc.Routes {
		if rc.Routes[ri].HttpMethod == "" && len(rc.Routes[ri].HttpMethods) == 0 {
			return fmt.Errorf("routes[%d] HTTP method is required", ri)
		}
		if rc.Routes[ri].RelativePath == "" && len(rc.Routes[ri].RelativePaths) == 0 {
			return fmt.Errorf("routes[%d] RelativePath is required", ri)
		}
		// validate route params (and warm regex cache)
		for pi, p := range rc.Routes[ri].Params {
			if err := p.Validate(); err != nil {
				return fmt.Errorf("routes[%d].params[%d]: %w", ri, pi, err)
			}
		}
		for rj, rule := range rc.Routes[ri].Rules {
			if err := rule.Validate(); err != nil {
				return fmt.Errorf("routes[%d].rules[%d]: %w", ri, rj, err)
			}
		}
	}
	return nil
}

// nolint: cyclop
func (r *RuleConfig) Validate() error {
	var errs []string

	if len(r.Cases) == 0 {
		if r.Format == "" {
			errs = append(errs, "Format is required when cases is empty")
		}
		if n := strings.Count(r.Format, "%s"); n != len(r.ParamNames) {
			errs = append(errs, fmt.Sprintf("Format %%s count (%d) must equal ParamNames length (%d)", n, len(r.ParamNames)))
		}
	}
	if len(r.Cases) > 0 {
		if r.Format != "" {
			errs = append(errs, "Format must be empty when cases are present")
		}
		if len(r.ParamNames) > 0 {
			errs = append(errs, "ParamNames must be empty when cases are present")
		}
	}
	for i, c := range r.Cases {
		if c.When == "" {
			errs = append(errs, fmt.Sprintf("cases[%d].when is required", i))
			continue
		}
		if c.Format == "" {
			errs = append(errs, fmt.Sprintf("cases[%d].format is required", i))
			continue
		}

		switch c.When {
		case "true", "false":
			// valid literals - do nothing
		default:
			if _, err := compileWhen(c.When); err != nil {
				errs = append(errs, fmt.Sprintf("cases[%d].when %q is invalid: %v", i, c.When, err))
			}
		}
		if n := strings.Count(c.Format, "%s"); n != len(c.ParamNames) {
			errs = append(errs, fmt.Sprintf("cases[%d].format %%s count (%d) must equal ParamNames length (%d)", i, n, len(c.ParamNames)))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("rule validation: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (p *ParamConfig) Validate() error {
	if !strings.EqualFold(strings.TrimSpace(p.Function), "regex") {
		return nil
	}
	if strings.TrimSpace(p.Expr) == "" {
		return fmt.Errorf("regex pattern (Expr) is empty for %s", p.Name)
	}
	if _, err := getCachedRegex(p.Expr); err != nil {
		return fmt.Errorf("invalid regex %q: %w", p.Expr, err)
	}
	return nil
}

// nolint: cyclop, perfsprint
func describeValidationErrors(err error) string {
	var ves validator.ValidationErrors
	if !errors.As(err, &ves) {
		return err.Error()
	}

	lines := make([]string, 0, len(ves))
	for _, fe := range ves {
		path := fe.StructNamespace()
		if dot := strings.Index(path, "."); dot != -1 {
			path = path[dot+1:]
		}
		switch fe.Tag() {
		case "required":
			lines = append(lines, fmt.Sprintf("%s: is required", path))
		case "oneof":
			allowed := strings.Fields(fe.Param())
			lines = append(lines, fmt.Sprintf("%s: must be one of %v; got %v", path, allowed, fe.Value()))
		case "dive":
			lines = append(lines, fmt.Sprintf("%s: has invalid item(s)", path))
		case "param_function":
			allowed := make([]string, 0, len(builtinFunc))
			for k := range builtinFunc {
				allowed = append(allowed, k)
			}
			sort.Strings(allowed)
			lines = append(lines, fmt.Sprintf("%s: unknown function %v; allowed=%v", path, fe.Value(), allowed))
		default:
			if fe.Param() != "" {
				lines = append(lines, fmt.Sprintf("%s: failed %s (%s); got %v", path, fe.Tag(), fe.Param(), fe.Value()))
			} else {
				lines = append(lines, fmt.Sprintf("%s: failed %s; got %v", path, fe.Tag(), fe.Value()))
			}
		}
	}
	return strings.Join(lines, " | ")
}
