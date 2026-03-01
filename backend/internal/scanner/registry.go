package scanner

import (
	"fmt"
	"sync"

	"github.com/redteam/agentic-scanner/internal/modules"
)

// ModuleRegistry manages available scanning modules
type ModuleRegistry struct {
	modules map[string]modules.Module
	mu      sync.RWMutex
}

// NewModuleRegistry creates a new empty module registry
func NewModuleRegistry() *ModuleRegistry {
	return &ModuleRegistry{
		modules: make(map[string]modules.Module),
	}
}

// Register adds a module to the registry
func (r *ModuleRegistry) Register(module modules.Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.modules[module.Name()] = module
}

// Get retrieves a module by name
func (r *ModuleRegistry) Get(name string) (modules.Module, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	module, ok := r.modules[name]
	if !ok {
		return nil, fmt.Errorf("module not found: %s", name)
	}
	return module, nil
}

// ListModules returns all registered module info
func (r *ModuleRegistry) ListModules() []modules.ModuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var infos []modules.ModuleInfo
	for _, module := range r.modules {
		infos = append(infos, modules.ModuleInfo{
			Name:        module.Name(),
			Description: module.Description(),
			Category:    getModuleCategory(module.Name()),
		})
	}
	return infos
}

func getModuleCategory(name string) string {
	switch name {
	case "recon":
		return "reconnaissance"
	case "web":
		return "web"
	case "api":
		return "api"
	case "agentic":
		return "ai-agent"
	case "intel":
		return "intelligence"
	default:
		return "other"
	}
}
