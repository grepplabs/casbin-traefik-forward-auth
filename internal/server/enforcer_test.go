package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/grepplabs/casbin-forward-auth/internal/config"
	"github.com/grepplabs/casbin-forward-auth/internal/models"
	casbinkube "github.com/grepplabs/casbin-kube"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newAdapter_Unknown(t *testing.T) {
	cfg := &config.CasbinConfig{Adapter: "not-supported"}
	a, err := newAdapter(cfg)
	require.Error(t, err)
	assert.Nil(t, a)
	assert.Contains(t, err.Error(), "unknown casbin adapter")
}

func Test_newAdapter_File(t *testing.T) {
	cfg := &config.CasbinConfig{
		Adapter: config.AdapterFile,
		AdapterFile: config.CasbinAdapterFileConfig{
			PolicyPath: "policy.csv", // existence not required for constructor
		},
	}
	a, err := newAdapter(cfg)
	require.NoError(t, err)
	require.NotNil(t, a)

	_, ok := a.(*fileadapter.Adapter)
	assert.True(t, ok, "expected *fileadapter.Adapter")
}

func Test_newAdapter_Kube(t *testing.T) {
	cfg := &config.CasbinConfig{
		Adapter: config.AdapterKube,
		AdapterKube: config.CasbinAdapterKubeConfig{
			KubeConfig: casbinkube.KubeConfig{
				Context:   "",
				Namespace: "",
				Path:      "",
				Labels:    nil,
			},
		},
	}

	a, err := newAdapter(cfg)
	if err != nil {
		t.Skipf("skipping kube adapter check (constructor requires actual kube env): %v", err)
	}
	require.NotNil(t, a)

	_, ok := a.(*casbinkube.Adapter)
	assert.True(t, ok, "expected *casbinkube.Adapter")
}

func Test_newModel_FromEmbeddedFS(t *testing.T) {
	cfg := &config.CasbinConfig{
		Model: "rbac_model.conf",
	}

	m, err := newModel(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)

	require.IsType(t, model.Model{}, m)
	for _, sec := range []string{"r", "p", "e", "m"} {
		_, ok := m[sec]
		assert.Truef(t, ok, "expected section %q to be present", sec)
	}
}

func Test_newModel_FromFileURL_OK(t *testing.T) {
	data, err := models.FS.ReadFile("rbac_model.conf")
	require.NoError(t, err, "embedded rbac_model.conf must exist")

	dir := t.TempDir()
	p := filepath.Join(dir, "model.conf")
	require.NoError(t, os.WriteFile(p, data, 0o600))

	cfg := &config.CasbinConfig{
		Model: "file://" + p,
	}

	m, err := newModel(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	require.IsType(t, model.Model{}, m)
}

func Test_newModel_FileURL_NotFound(t *testing.T) {
	cfg := &config.CasbinConfig{
		Model: "file:///tmp/does/not/exist.conf",
	}
	m, err := newModel(cfg)
	require.Error(t, err)
	assert.Nil(t, m)
}

func Test_newModel_FromFS_MissingName(t *testing.T) {
	cfg := &config.CasbinConfig{
		Model: "does_not_exist.conf",
	}
	m, err := newModel(cfg)
	require.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "error reading model")
}
