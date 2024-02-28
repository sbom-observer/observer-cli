package k8s

// copy of internal

import (
	"github.com/google/go-containerregistry/pkg/name"
	"strings"
)

type ImageReference struct {
	Reference string
	Name      string
	Tag       string
	Digest    string
	Registry  string
}

func (ir ImageReference) Identifier() string {
	if ir.Digest != "" {
		return ir.Digest
	}

	return ir.Tag
}

func (ir ImageReference) String() string {
	return ir.Reference
}

func ParseImageReference(image string) (ImageReference, error) {
	image = strings.TrimPrefix(image, "docker://")
	image = strings.TrimPrefix(image, "docker-pullable://")

	ref, err := name.ParseReference(image)
	if err != nil {
		return ImageReference{}, err
	}

	var tag, digest string
	identifier := ref.Identifier()
	if strings.HasPrefix(identifier, "sha256:") {
		digest = identifier
	} else {
		tag = identifier
	}

	return ImageReference{
		Reference: ref.String(),
		//Name:      ref.Context().Name(),
		Name:     ref.Context().RepositoryStr(),
		Registry: ref.Context().RegistryStr(),
		Tag:      tag,
		Digest:   digest,
	}, nil
}
