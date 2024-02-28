package k8s

import "time"

// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.26/#containerstatus-v1-core

type Container struct {
	Image string `json:"image"`
	//ImagePullPolicy string `json:"imagePullPolicy"`
	Name string `json:"name"`
	//Command      []string `json:"command,omitempty"`
}

type ContainerStatus struct {
	ContainerID string `json:"containerID"`
	Image       string `json:"image"`
	ImageID     string `json:"imageID"`
	Name        string `json:"name"`
	//LastState   struct {
	//} `json:"lastState"`
	//Ready        bool   `json:"ready"`
	//RestartCount int    `json:"restartCount"`
	//Started      bool   `json:"started"`
	//State        struct {
	//	Running struct {
	//		StartedAt time.Time `json:"startedAt"`
	//	} `json:"running"`
	//} `json:"state"`
}

type NodeInfo struct {
	Architecture            string `json:"architecture"`
	BootID                  string `json:"bootID"`
	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
	KernelVersion           string `json:"kernelVersion"`
	KubeProxyVersion        string `json:"kubeProxyVersion"`
	KubeletVersion          string `json:"kubeletVersion"`
	MachineID               string `json:"machineID"`
	OperatingSystem         string `json:"operatingSystem"`
	OsImage                 string `json:"osImage"`
	SystemUUID              string `json:"systemUUID"`
}

type OwnerReference struct {
	ApiVersion         string `json:"apiVersion"`
	BlockOwnerDeletion bool   `json:"blockOwnerDeletion,omitempty"`
	Controller         bool   `json:"controller"`
	Kind               string `json:"kind"`
	Name               string `json:"name"`
	Uid                string `json:"uid"`
}

type Item struct {
	ApiVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		CreationTimestamp time.Time         `json:"creationTimestamp"`
		Labels            map[string]string `json:"labels,omitempty"`
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace,omitempty"`
		ResourceVersion   string            `json:"resourceVersion"`
		Uid               string            `json:"uid"`
		//GenerateName    string `json:"generateName,omitempty"`
		OwnerReferences []OwnerReference `json:"ownerReferences,omitempty"`
	} `json:"metadata"`
	Spec struct {
		Type                string      `json:"type,omitempty"`
		Containers          []Container `json:"containers,omitempty"`
		EphemeralContainers []Container `json:"ephemeralContainers,omitempty"`
		InitContainers      []Container `json:"initContainers,omitempty"`
		NodeName            string      `json:"nodeName,omitempty"`
	} `json:"spec"`
	Status struct {
		ContainerStatuses          []ContainerStatus `json:"containerStatuses,omitempty"`
		EphemeralContainerStatuses []ContainerStatus `json:"ephemeralContainerStatuses,omitempty"`
		InitContainerStatuses      []ContainerStatus `json:"initContainerStatuses,omitempty"`

		NodeInfo NodeInfo `json:"nodeInfo,omitempty"`
		Images   []struct {
			Names []string `json:"names,omitempty"`
		} `json:"images,omitempty"`
	} `json:"status"`
}

type KubectlSnapshot struct {
	ApiVersion string `json:"apiVersion"`
	Items      []Item `json:"items"`
}
