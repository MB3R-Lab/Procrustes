package scan_test

import (
	"testing"

	"github.com/MB3R-Lab/Procrustes/internal/scan"
	"github.com/MB3R-Lab/Procrustes/internal/source"
)

func TestInventoriesSupportedTracingBackends(t *testing.T) {
	files := []source.File{
		{Ref: "zipkin/deployment.yaml", Raw: []byte("image: openzipkin/zipkin:3")},
		{Ref: "tempo/deployment.yaml", Raw: []byte("image: grafana/tempo:2")},
		{Ref: "skywalking/deployment.yaml", Raw: []byte("image: apache/skywalking-oap-server:10")},
	}
	inventory := scan.Files(files)
	for _, wanted := range []string{"zipkin", "tempo", "skywalking"} {
		found := false
		for _, item := range inventory.TraceSystems {
			if item.System == wanted && item.Role == "backend" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s backend was not inventoried: %+v", wanted, inventory.TraceSystems)
		}
	}
}
