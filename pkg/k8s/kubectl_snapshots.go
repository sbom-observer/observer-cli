package k8s

import (
	"encoding/json"
	"fmt"
	"golang.org/x/exp/maps"
	"log/slog"
	"net/url"
)

// copy of SO internal

const (
	KindNamespace             = "Namespace"
	KindNode                  = "Node"
	KindPod                   = "Pod"
	KindJob                   = "Job"
	KindCronJob               = "CronJob"
	KindReplicaSet            = "ReplicaSet"
	KindReplicationController = "ReplicationController"
	KindStatefulSet           = "StatefulSet"
	KindDaemonSet             = "DaemonSet"
	KindDeployment            = "Deployment"

	//Deployments            = "deployments"
	//ReplicaSets            = "replicasets"
	//ReplicationControllers = "replicationcontrollers"
	//StatefulSets           = "statefulsets"
	//DaemonSets             = "daemonsets"
	//CronJobs               = "cronjobs"
	//Services               = "services"
	//ServiceAccounts        = "serviceaccounts"
	//Jobs                   = "jobs"
	//Pods                   = "pods"
	//ConfigMaps             = "configmaps"
	//Roles                  = "roles"
	//RoleBindings           = "rolebindings"
	//NetworkPolicies        = "networkpolicies"
	//Ingresses              = "ingresses"
	//ResourceQuotas         = "resourcequotas"
	//LimitRanges            = "limitranges"
	//ClusterRoles           = "clusterroles"
	//ClusterRoleBindings    = "clusterrolebindings"
	//Nodes                  = "nodes"
	//k8sComponentNamespace  = "kube-system"
	//
	//serviceAccountDefault = "default"
)

type Snapshot struct {
	Resources []Resource
}

type Resource struct {
	Id                      string
	Namespace               string
	Kind                    string
	Labels                  map[string]string
	Name                    string
	Images                  []Image
	Arch                    string // nodes
	NodeName                string // name is unique in namespace
	OsImage                 string
	ContainerRuntimeVersion string
	//Credentials []docker.Auth
	//RawResource map[string]interface{}
}

type Image struct {
	Name          string
	Tag           string
	Digest        string
	RepositoryURL string
	ImageID       string
	Arch          string
}

func ParseKubetclSnapshot(bs []byte) (*Snapshot, error) {
	var snapshot KubectlSnapshot
	err := json.Unmarshal(bs, &snapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal kubectl snapshot: %w", err)
	}

	var resources []Resource
	for _, item := range snapshot.Items {
		resource, err := parseResource(item)
		if err != nil {
			slog.Error("failed to parse resource", "item", item, "err", err)
			continue
		}
		resources = append(resources, resource)
	}

	// set image arch from node arch
	nodeArches := map[string]string{}
	for _, node := range snapshot.Items {
		if node.Kind == KindNode {
			arch := node.Status.NodeInfo.Architecture
			nodeArches[node.Metadata.Name] = arch
		}
	}

	for i, resource := range resources {
		if resource.NodeName != "" {
			for j, image := range resource.Images {
				image.Arch = nodeArches[resource.NodeName]
				resources[i].Images[j] = image
			}
		}
	}

	return &Snapshot{
		Resources: resources,
	}, nil
}

func parseResource(input Item) (Resource, error) {
	resource := Resource{
		Kind:      input.Kind,
		Id:        input.Metadata.Uid,
		Name:      input.Metadata.Name,
		Namespace: input.Metadata.Namespace,
		Labels:    input.Metadata.Labels,
		NodeName:  input.Spec.NodeName,
	}

	// sanity check
	if resource.Kind == "" {
		return Resource{}, fmt.Errorf("resource is missing kind field")
	}

	if resource.Kind == KindPod && resource.Namespace == "" {
		return Resource{}, fmt.Errorf("pod resource is missing Namespace field")
	}

	// find all containers and images
	resource.Images = parseImages(input)

	if resource.Kind == KindNode || resource.Kind == KindPod {
		resource.Arch = input.Status.NodeInfo.Architecture
	}

	if resource.Kind == KindNode {
		resource.OsImage = input.Status.NodeInfo.OperatingSystem
		resource.ContainerRuntimeVersion = input.Status.NodeInfo.ContainerRuntimeVersion
	}

	return resource, nil
}

func parseImages(resource Item) []Image {
	images := map[string]Image{}

	// first we gather all the images specs {"containers", "ephemeralContainers", "initContainers"}
	for _, containers := range [][]Container{resource.Spec.Containers, resource.Spec.EphemeralContainers, resource.Spec.InitContainers} {
		for _, container := range containers {
			container.Image, _ = url.QueryUnescape(container.Image)

			// docker.io/kubernetesui/dashboard:v2.7.0@sha256:2e500d29e9d5f4a086b908eb8dfe7ecac57d2ab09d65b24f588b1d449841ef93
			ref, err := ParseImageReference(container.Image)
			if err != nil {
				slog.Error("failed to parse image reference", "image", container.Image, "err", err)
				images[container.Name] = Image{Name: container.Image}
				continue
			}

			image := Image{
				Name:   ref.Name,
				Tag:    ref.Tag,
				Digest: ref.Digest,
			}

			if ref.Registry != "" {
				image.RepositoryURL = ref.Registry + "/" + ref.Name
			}

			images[container.Name] = image
		}
	}

	for _, containers := range [][]ContainerStatus{resource.Status.ContainerStatuses, resource.Status.EphemeralContainerStatuses, resource.Status.InitContainerStatuses} {
		for _, status := range containers {
			status.Image, _ = url.QueryUnescape(status.Image)

			image, found := images[status.Name]
			if !found {
				slog.Error("found a containerStatus for an images not found in spec", "statusImage", status.Image, "spec", images)
				image = Image{
					Name: status.Image,
				}
			}

			image.ImageID = status.ImageID

			// TODO: this is probably not correct
			if ref, err := ParseImageReference(image.ImageID); err == nil {
				image.Digest = ref.Digest
			}

			//if strings.HasPrefix(status.ImageID, "docker-pullable://sha256:") && image.Digest == "" {
			//	image.Digest = strings.TrimPrefix(status.ImageID, "docker-pullable://sha256:")
			//}

			images[status.Name] = image
		}
	}

	// TODO: handle other Kinds
	//	case KindCronJob:
	//		return []string{"spec", "jobTemplate", "spec", "template", "spec"}
	//	default:
	//		return []string{"spec", "template", "spec"}

	return maps.Values(images)
}
