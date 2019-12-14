package caddy

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/sarge/cors/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// CorsRule stores the parsed rules
type CorsRule struct {
	Conf *cors.Config
	Path string
}

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("cors", parseCaddyfile)
}

// Middleware implements an HTTP handler that writes directs the requests
// made with an upper case prefix to a lower case version
type Middleware struct {
	Rules []*CorsRule `json:"rules,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cors",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	for _, rule := range m.Rules {
		if strings.HasPrefix(strings.ToLower(r.URL.Path), rule.Path) {
			rule.Conf.HandleRequest(w, r)
			if cors.IsPreflight(r) {
				w.WriteHeader(200)
				return nil
			}
			break
		}
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(c *caddyfile.Dispenser) error {

	for c.Next() {
		rule := &CorsRule{Path: "/", Conf: cors.Default()}
		args := c.RemainingArgs()

		anyOrigins := false
		if len(args) > 0 {
			rule.Path = args[0]
		}
		for i := 1; i < len(args); i++ {
			if !anyOrigins {
				rule.Conf.AllowedOrigins = nil
			}
			rule.Conf.AllowedOrigins = append(rule.Conf.AllowedOrigins, strings.Split(args[i], ",")...)
			anyOrigins = true
		}

		for c.NextBlock(0) {
			switch c.Val() {
			case "origin":
				if !anyOrigins {
					rule.Conf.AllowedOrigins = nil
				}
				args := c.RemainingArgs()
				for _, domain := range args {
					rule.Conf.AllowedOrigins = append(rule.Conf.AllowedOrigins, strings.Split(domain, ",")...)
				}
				anyOrigins = true

			case "origin_regexp":
				arg, err := singleArg(c, "origin_regexp")
				if err != nil {
					return err
				}
				r, err := regexp.Compile(arg)

				if err != nil {
					return c.Errf("could no compile regexp: %s", err)
				}

				if !anyOrigins {
					rule.Conf.AllowedOrigins = nil
					anyOrigins = true
				}

				rule.Conf.OriginRegexps = append(rule.Conf.OriginRegexps, r)

			case "methods":
				arg, err := singleArg(c, "methods")
				if err != nil {
					return err
				}
				rule.Conf.AllowedMethods = arg
			case "allow_credentials":
				arg, err := singleArg(c, "allow_credentials")
				if err != nil {
					return err
				}
				var b bool
				if arg == "true" {
					b = true
				} else if arg != "false" {
					return c.Errf("allow_credentials must be true or false.")
				}
				rule.Conf.AllowCredentials = &b

			case "max_age":
				arg, err := singleArg(c, "max_age")
				if err != nil {
					return err
				}
				i, err := strconv.Atoi(arg)
				if err != nil {
					return c.Err("max_age must be valid int")
				}
				rule.Conf.MaxAge = i

			case "allowed_headers":
				arg, err := singleArg(c, "allowed_headers")
				if err != nil {
					return err
				}
				rule.Conf.AllowedHeaders = arg
			case "exposed_headers":
				arg, err := singleArg(c, "exposed_headers")
				if err != nil {
					return err
				}
				rule.Conf.ExposedHeaders = arg

			default:
				return c.Errf("Unknown cors config item: %s", c.Val())
			}
		}
		m.Rules = append(m.Rules, rule)
	}

	return nil
}

func singleArg(c *caddyfile.Dispenser, desc string) (string, error) {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return "", c.Errf("%s expects exactly one argument", desc)
	}
	return args[0], nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
