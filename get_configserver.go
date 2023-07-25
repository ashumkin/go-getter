package getter

import (
	"bytes"
	"fmt"
	"github.com/vmware-labs/yaml-jsonpath/pkg/yamlpath"
	"gopkg.in/yaml.v3"
	"io"
	"net/url"
	"os"
)

// ConfigServerGetter is a Getter implementation that will download from an HTTP
// endpoint.
//
// For file downloads, HTTP is used directly.
type ConfigServerGetter struct {
	httpGetter HttpGetter
}

func (g *ConfigServerGetter) SetClient(c *Client) {
	g.httpGetter.SetClient(c)
}

func (g *ConfigServerGetter) ClientMode(u *url.URL) (ClientMode, error) {
	return g.httpGetter.ClientMode(u)
}

func (g *ConfigServerGetter) Get(dst string, u *url.URL) error {
	return g.httpGetter.Get(dst, u)
}

// GetFile. see HttpGetter.GetFile
// just XTerraformGetDisabled=true
// after a file is received and `xpath` is not empty
// then it is loaded as `format`,
// and xpath's result type is interpreted as a map (unless `type=list` specified)
func (g *ConfigServerGetter) GetFile(dst string, u *url.URL) error {
	// Extract some query parameters we use
	var xpath, format, _type, newKey string
	q := u.Query()
	if len(q) > 0 {
		xpath = q.Get("xpath")
		q.Del("xpath")
		format = q.Get("format")
		q.Del("format")
		_type = q.Get("type")
		q.Del("type")
		newKey = q.Get("newkey")
		q.Del("newkey")

		// Copy the URL
		var newU = *u
		u = &newU
		u.RawQuery = q.Encode()
	}
	err := g.httpGetter.GetFile(dst, u)
	if err != nil {
		return err
	}

	const yaml = "yaml"
	if len(format) == 0 && len(xpath) > 0 {
		// default format is YAML (if value is specified)
		format = yaml
	}
	var buf *bytes.Buffer
	if format == yaml {
		var y []byte
		y, err = g.readYAML(dst)
		if err != nil {
			return err
		}

		buf, err = g.xpathYAML(dst, y, xpath, _type, newKey)
		if err != nil {
			return err
		}
	} else if len(format) > 0 {
		return fmt.Errorf("unsupported format %s, yet", format)
	}
	if buf != nil {
		err = g.save(dst, buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *ConfigServerGetter) save(dst string, buf *bytes.Buffer) error {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, g.fileMode())
	if err != nil {
		return fmt.Errorf("cannot open file (%s): %v", dst, err)
	}
	defer f.Close()
	_, err = f.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("error saving file %s: %v", dst, err)
	}
	return nil
}

func (g *ConfigServerGetter) xpathYAML(dst string, y []byte, xpath, resultType, newKey string) (*bytes.Buffer, error) {
	var n yaml.Node

	err := yaml.Unmarshal(y, &n)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal data from file(%s): %v", dst, err)
	}

	p, err := yamlpath.NewPath(xpath)
	if err != nil {
		return nil, fmt.Errorf("cannot create path: %v", err)
	}

	qry, err := p.Find(&n)
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %v", err)
	}
	if len(qry) > 1 && resultType != "list" {
		return nil, fmt.Errorf("unexpected result: more elements than 1: %d", len(qry))
	}

	buf := bytes.NewBuffer(nil)
	if qry == nil {
		return buf, nil
	}
	node := qry[0]
	e := yaml.NewEncoder(buf)
	defer e.Close()
	e.SetIndent(2)
	if len(newKey) > 0 {
		node = g.newKeyedNodes(newKey, node)
	}

	err = e.Encode(node)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal node: %v", err)
	}
	return buf, nil
}

func (g *ConfigServerGetter) newKeyedNodes(newKey string, node *yaml.Node) *yaml.Node {
	nn := yaml.Node{
		Kind: yaml.DocumentNode,
		Content: []*yaml.Node{{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{
					Kind:  yaml.ScalarNode,
					Value: newKey,
				},
				node,
			},
		}},
	}
	return &nn
}

func (g *ConfigServerGetter) readYAML(dst string) ([]byte, error) {
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, g.fileMode())
	if err != nil {
		return nil, fmt.Errorf("cannot open file (%s): %v", dst, err)
	}
	defer f.Close()
	y, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read all file (%s): %v", dst, err)
	}
	return y, nil
}

func (g *ConfigServerGetter) fileMode() os.FileMode {
	return g.httpGetter.client.mode(0666)
}

func NewConfigServerGetter() *ConfigServerGetter {
	return &ConfigServerGetter{httpGetter: HttpGetter{
		Netrc:                 true,
		XTerraformGetDisabled: true,
	}}
}
