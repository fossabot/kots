package kotsadm

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func migrationsPod(deployOptions DeployOptions) *corev1.Pod {
	name := fmt.Sprintf("kotsadm-migrations-%d", time.Now().Unix())

	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: deployOptions.Namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyOnFailure,
			Containers: []corev1.Container{
				{
					Image:           fmt.Sprintf("kotsadm/kotsadm-migrations:%s", kotsadmTag()),
					ImagePullPolicy: corev1.PullAlways,
					Name:            name,
					Env: []corev1.EnvVar{
						{
							Name:  "SCHEMAHERO_DRIVER",
							Value: "postgres",
						},
						{
							Name:  "SCHEMAHERO_SPEC_FILE",
							Value: "/tables",
						},
						{
							Name:  "SCHEMAHERO_URI",
							Value: fmt.Sprintf("postgresql://kotsadm:%s@kotsadm-postgres/kotsadm?connect_timeout=10&sslmode=disable", deployOptions.PostgresPassword),
						},
					},
				},
			},
		},
	}

	return pod
}
