package k8s

// copy of internal

import (
	"fmt"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestParseImageRefs(t *testing.T) {
	r := require.New(t)
	image := "docker.io/kubernetesui/dashboard:v2.7.0@sha256:2e500d29e9d5f4a086b908eb8dfe7ecac57d2ab09d65b24f588b1d449841ef93"
	//image := "kubernetesui/dashboard"
	ref, err := name.ParseReference(image)
	r.NoError(err)

	s := ref.String()
	n := ref.Name()
	i := ref.Identifier()
	c := ref.Context()

	fmt.Printf(" s=%s\n n=%s\n i=%s\n c=%+v\n", s, n, i, c.RegistryStr())
	fmt.Printf(" s=%s\n n=%s\n i=%s\n c=%+v\n", s, n, i, c.String())
}

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		image   string
		want    ImageReference
		wantErr bool
	}{
		{
			image: "docker.io/kubernetesui/dashboard:v2.7.0@sha256:2e500d29e9d5f4a086b908eb8dfe7ecac57d2ab09d65b24f588b1d449841ef93",
			want: ImageReference{
				Name:     "kubernetesui/dashboard",
				Digest:   "sha256:2e500d29e9d5f4a086b908eb8dfe7ecac57d2ab09d65b24f588b1d449841ef93",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
		{
			image: "docker.io/kubernetesui/dashboard@sha256:2e500d29e9d5f4a086b908eb8dfe7ecac57d2ab09d65b24f588b1d449841ef93",
			want: ImageReference{
				Name:     "kubernetesui/dashboard",
				Digest:   "sha256:2e500d29e9d5f4a086b908eb8dfe7ecac57d2ab09d65b24f588b1d449841ef93",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
		{
			image: "docker.io/kubernetesui/dashboard:v2.7.0",
			want: ImageReference{
				Name:     "kubernetesui/dashboard",
				Tag:      "v2.7.0",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
		{
			image: "docker.io/kubernetesui/dashboard",
			want: ImageReference{
				Name:     "kubernetesui/dashboard",
				Tag:      "latest",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
		{
			image: "kubernetesui/dashboard",
			want: ImageReference{
				Name:     "kubernetesui/dashboard",
				Tag:      "latest",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
		{
			image: "docker-pullable://docker/getting-started@sha256:d79336f4812b6547a53e735480dde67f8f8f7071b414fbd9297609ffb989abc1",
			want: ImageReference{
				Name:     "docker/getting-started",
				Digest:   "sha256:d79336f4812b6547a53e735480dde67f8f8f7071b414fbd9297609ffb989abc1",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
		{
			image: "docker://docker/getting-started@sha256:d79336f4812b6547a53e735480dde67f8f8f7071b414fbd9297609ffb989abc1",
			want: ImageReference{
				Name:     "docker/getting-started",
				Digest:   "sha256:d79336f4812b6547a53e735480dde67f8f8f7071b414fbd9297609ffb989abc1",
				Registry: "index.docker.io",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			got, err := ParseImageReference(tt.image)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseImageReference() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			image := strings.TrimPrefix(tt.image, "docker://")
			image = strings.TrimPrefix(image, "docker-pullable://")

			require.Equalf(t, image, got.Reference, "Reference")
			require.Equalf(t, tt.want.Name, got.Name, "Name")
			require.Equalf(t, tt.want.Tag, got.Tag, "Tag")
			require.Equalf(t, tt.want.Digest, got.Digest, "Digest")
			require.Equalf(t, tt.want.Registry, got.Registry, "Registry")
		})
	}
}
