package server

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/grepplabs/casbin-forward-auth/internal/config"
	"github.com/grepplabs/casbin-forward-auth/internal/models"
	casbinkube "github.com/grepplabs/casbin-kube"
	"github.com/grepplabs/loggo/zlog"
)

func newLifecycleEnforcer(cfg *config.CasbinConfig) (*LifecycleEnforcer, error) {
	a, err := newAdapter(cfg)
	if err != nil {
		return nil, fmt.Errorf("new casbin adapter %w", err)
	}
	m, err := newModel(cfg)
	if err != nil {
		return nil, fmt.Errorf("new model %w", err)
	}
	enforcer, err := casbin.NewSyncedEnforcer(m, a)
	if err != nil {
		return nil, fmt.Errorf("error creating enforcer: %w", err)
	}
	enforcer.EnableAutoSave(false)

	if cfg.AutoLoadPolicyInterval > 0 {
		zlog.Infof("casbin policy auto-reload interval: %v", cfg.AutoLoadPolicyInterval)
		enforcer.StartAutoLoadPolicy(cfg.AutoLoadPolicyInterval)
	}
	cr := &LifecycleEnforcer{SyncedEnforcer: enforcer}

	starter, closer, err := newInformer(cfg, enforcer)
	if err != nil {
		return nil, fmt.Errorf("error creating informer %w", err)
	}
	if closer != nil {
		cr.AddCloser(closer)
	}
	if starter != nil {
		cr.AddStarter(starter)
	}
	return cr, nil
}

func newAdapter(cfg *config.CasbinConfig) (persist.Adapter, error) {
	adapter := strings.ToLower(cfg.Adapter)
	zlog.Infof("init '%s' adapter", adapter)

	switch adapter {
	case config.AdapterFile:
		return fileadapter.NewAdapter(cfg.AdapterFile.PolicyPath), nil
	case config.AdapterKube:
		return casbinkube.NewAdapter(&casbinkube.AdapterConfig{KubeConfig: cfg.AdapterKube.KubeConfig})
	default:
		return nil, fmt.Errorf("unknown casbin adapter: %s", adapter)
	}
}

func newInformer(cfg *config.CasbinConfig, enforcer casbin.IEnforcer) (Starter, io.Closer, error) {
	// only kube
	if strings.ToLower(cfg.Adapter) != config.AdapterKube || cfg.AdapterKube.DisableInformer {
		return nil, nil, nil
	}
	zlog.Infof("init 'kube' informer for namespace '%s' labels '%v'", cfg.AdapterKube.Namespace, cfg.AdapterKube.Labels)

	informer, err := casbinkube.NewInformer(&casbinkube.InformerConfig{KubeConfig: cfg.AdapterKube.KubeConfig}, enforcer)
	if err != nil {
		return nil, nil, err
	}
	return informer, closeFunc(informer.Close), nil
}

func newModel(cfg *config.CasbinConfig) (model.Model, error) {
	zlog.Infof("init '%s' model", cfg.Model)

	if strings.HasPrefix(cfg.Model, "file://") {
		modelPath := strings.TrimPrefix(cfg.Model, "file://")
		return model.NewModelFromFile(modelPath)
	} else {
		return models.LoadModelFromFS(cfg.Model)
	}
}

type Starter interface {
	Start(ctx context.Context) error
}

type LifecycleEnforcer struct {
	*casbin.SyncedEnforcer
	closers Closers
	start   Starter
}

func (e *LifecycleEnforcer) AddCloser(c io.Closer) {
	if c != nil {
		e.closers.Add(c)
	}
}

func (e *LifecycleEnforcer) AddStarter(s Starter) {
	e.start = s
}

func (e *LifecycleEnforcer) Close() error {
	if e == nil {
		return nil
	}
	return e.closers.Close()
}

func (e *LifecycleEnforcer) Start(ctx context.Context) error {
	if e.start != nil {
		return e.start.Start(ctx)
	}
	return nil
}
