//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package auditlogging

import (
	"context"

	operatorv1alpha1 "github.com/ibm/ibm-auditlogging-operator/pkg/apis/operator/v1alpha1"
	res "github.com/ibm/ibm-auditlogging-operator/pkg/resources"
	certmgr "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func (r *ReconcileAuditLogging) reconcileService(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("Service.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected := res.BuildAuditService(instance)
	found := &corev1.Service{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		if err := controllerutil.SetControllerReference(instance, expected, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new Service", "Service.Namespace", expected.Namespace, "Service.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new Service", "Service.Namespace", expected.Namespace,
				"Service.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// Service created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Service")
		return reconcile.Result{}, err
	} else if result := res.EqualServices(expected, found); result {
		// If ports are incorrect, delete it and requeue
		reqLogger.Info("Found ports are incorrect", "Found", found.Spec.Ports, "Expected", expected.Spec.Ports)
		err = r.client.Delete(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete Service", "Name", found.Name)
			return reconcile.Result{}, err
		}
		// Updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileAuditPolicyResources(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	var reqLogger = log.WithValues("instance.Name", instance.Name)
	var requeue = false
	expected := res.BuildAuditPolicyCRD(instance)
	found := &extv1beta1.CustomResourceDefinition{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new CRD
		reqLogger.Info("Creating a new Audit Policy CRD", "CRD.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && !errors.IsAlreadyExists(err) {
			reqLogger.Error(err, "Failed to create new CRD", expected.Namespace,
				"CRD.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// CRD created successfully - return and requeue
		requeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get CRD")
		return reconcile.Result{}, err
	}
	reqLogger = log.WithValues("CR.Namespace", instance.Namespace, "instance.Name", instance.Name)
	foundPolicy := &unstructured.Unstructured{}
	foundPolicy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   res.AuditPolicyGroup,
		Kind:    res.AuditPolicyKind,
		Version: res.AuditPolicyVersion,
	})
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: res.DefaultAuditPolicyName, Namespace: instance.Namespace}, foundPolicy)
	if err != nil && errors.IsNotFound(err) {
		policy, err := res.BuildAuditPolicyCR(instance)
		if err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new Audit Policy CR", "CR.Name", res.DefaultAuditPolicyName)
		err = r.client.Create(context.TODO(), policy)
		if err != nil && !errors.IsAlreadyExists(err) {
			reqLogger.Error(err, "Failed to create new CR", "CR.Name", res.DefaultAuditPolicyName)
			return reconcile.Result{}, err
		}
		// CR created successfully - return and requeue
		requeue = true
	} else if err != nil {
		reqLogger.Error(err, "Failed to get CR")
		return reconcile.Result{}, err
	}
	if requeue {
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcilePolicyControllerDeployment(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("Deployment.Namespace", instance.Namespace, "instance.Name", instance.Name)

	expected := res.BuildDeploymentForPolicyController(instance)
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: res.AuditPolicyControllerDeploy, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new Deployment
		if err := controllerutil.SetControllerReference(instance, expected, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new Audit Policy Controller Deployment", "Deployment.Namespace", expected.Namespace, "Deployment.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new Audit Policy Controller Deployment", "Deployment.Namespace", expected.Namespace,
				"Deployment.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// Deployment created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Deployment")
		return reconcile.Result{}, err
	} else if !res.EqualDeployments(expected, found) {
		// If spec is incorrect, update it and requeue
		found.ObjectMeta.Labels = expected.ObjectMeta.Labels
		found.Spec = expected.Spec
		err = r.client.Update(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Deployment", "Namespace", instance.Namespace, "Name", found.Name)
			return reconcile.Result{}, err
		}
		reqLogger.Info("Updating Audit Policy Controller Deployment", "Deployment.Name", found.Name)
		// Spec updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileAuditConfigMaps(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	var recResult reconcile.Result
	var recErr error

	for _, cm := range res.FluentdConfigMaps {
		recResult, recErr = r.reconcileConfig(instance, cm)
		if recErr != nil || recResult.Requeue {
			return recResult, recErr
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileConfig(instance *operatorv1alpha1.AuditLogging, configName string) (reconcile.Result, error) {
	reqLogger := log.WithValues("ConfigMap.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected, err := res.BuildConfigMap(instance, configName)
	if err != nil {
		reqLogger.Error(err, "Failed to create ConfigMap")
		return reconcile.Result{}, err
	}
	found := &corev1.ConfigMap{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: configName, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new ConfigMap
		if err := controllerutil.SetControllerReference(instance, expected, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new ConfigMap", "ConfigMap.Namespace", expected.Namespace, "ConfigMap.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new ConfigMap", "ConfigMap.Namespace", expected.Namespace,
				"ConfigMap.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// ConfigMap created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ConfigMap")
		return reconcile.Result{}, err
	}
	// ConfigMap was found, check for expected values

	if configName == res.FluentdDaemonSetName+"-"+res.SourceConfigName {
		// Ensure default port is used
		if result, ports := res.EqualSourceConfig(expected, found); !result {
			reqLogger.Info("Found source config is incorrect", "Found port", ports[0], "Expected port", ports[1])
			err = r.client.Delete(context.TODO(), found)
			if err != nil {
				reqLogger.Error(err, "Failed to delete ConfigMap", "Name", found.Name)
				return reconcile.Result{}, err
			}
			// Deleted - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}
	}
	var update = false
	if !res.EqualLabels(found.ObjectMeta.Labels, expected.ObjectMeta.Labels) {
		found.ObjectMeta.Labels = expected.ObjectMeta.Labels
		update = true
	}
	if configName == res.FluentdDaemonSetName+"-"+res.SplunkConfigName ||
		configName == res.FluentdDaemonSetName+"-"+res.QRadarConfigName {
		// Ensure match tags are correct
		if !res.EqualMatchTags(found) {
			// Keep customer SIEM configs
			data, err := res.BuildWithSIEMConfigs(found)
			if err != nil {
				reqLogger.Error(err, "Failed to get SIEM configs", "Name", found.Name)
				return reconcile.Result{}, err
			}
			if configName == res.FluentdDaemonSetName+"-"+res.SplunkConfigName {
				found.Data[res.SplunkConfigKey] = data
			} else {
				found.Data[res.QRadarConfigKey] = data
			}
			update = true
		}
	}
	if update {
		err = r.client.Update(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to update ConfigMap", "Name", found.Name)
			return reconcile.Result{}, err
		}
		// Updated - return and requeue
		reqLogger.Info("Updating ConfigMap", "ConfigMap.Name", found.Name)
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileFluentdDaemonSet(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("Daemonset.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected := res.BuildDaemonForFluentd(instance)
	found := &appsv1.DaemonSet{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: res.FluentdDaemonSetName, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new DaemonSet
		if err := controllerutil.SetControllerReference(instance, expected, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new Fluentd DaemonSet", "Daemonset.Namespace", expected.Namespace, "Daemonset.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new Fluentd DaemonSet", "Daemonset.Namespace", expected.Namespace,
				"Daemonset.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// DaemonSet created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get DaemonSet")
		return reconcile.Result{}, err
	} else if !res.EqualDaemonSets(expected, found) {
		// If spec is incorrect, update it and requeue
		found.ObjectMeta.Labels = expected.ObjectMeta.Labels
		// Keep hostAliases
		temp := found.Spec.Template.Spec.HostAliases
		found.Spec = expected.Spec
		found.Spec.Template.Spec.HostAliases = temp
		err = r.client.Update(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to update Daemonset", "Namespace", instance.Namespace, "Name", found.Name)
			return reconcile.Result{}, err
		}
		reqLogger.Info("Updating Fluentd DaemonSet", "Daemonset.Name", found.Name)
		// Spec updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileAuditCerts(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	var recResult reconcile.Result
	var recErr error
	recResult, recErr = r.reconcileAuditCertificate(instance, res.AuditLoggingHTTPSCertName)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}
	recResult, recErr = r.reconcileAuditCertificate(instance, res.AuditLoggingCertName)
	if recErr != nil || recResult.Requeue {
		return recResult, recErr
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileAuditCertificate(instance *operatorv1alpha1.AuditLogging, name string) (reconcile.Result, error) {
	reqLogger := log.WithValues("Certificate.Namespace", instance.Namespace, "Instance.Name", instance.Name)
	expectedCert := res.BuildCertsForAuditLogging(instance, instance.Spec.Fluentd.ClusterIssuer, name)
	foundCert := &certmgr.Certificate{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expectedCert.Name, Namespace: expectedCert.ObjectMeta.Namespace}, foundCert)
	if err != nil && errors.IsNotFound(err) {
		// Set Audit Logging instance as the owner and controller of the Certificate
		if err := controllerutil.SetControllerReference(instance, expectedCert, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new Fluentd Certificate", "Certificate.Namespace", expectedCert.Namespace, "Certificate.Name", expectedCert.Name)
		err = r.client.Create(context.TODO(), expectedCert)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new Fluentd Certificate", "Certificate.Namespace", expectedCert.Namespace,
				"Certificate.Name", expectedCert.Name)
			return reconcile.Result{}, err
		}
		// Certificate created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Certificate")
		return reconcile.Result{}, err
	} else if result := res.EqualCerts(expectedCert, foundCert); result {
		// If spec is incorrect, update it and requeue
		reqLogger.Info("Found Certificate spec is incorrect", "Found", foundCert.Spec, "Expected", expectedCert.Spec)
		foundCert.Spec = expectedCert.Spec
		err = r.client.Update(context.TODO(), foundCert)
		if err != nil {
			reqLogger.Error(err, "Failed to update Certificate", "Namespace", foundCert.ObjectMeta.Namespace, "Name", foundCert.Name)
			return reconcile.Result{}, err
		}
		reqLogger.Info("Updating Fluentd Certificate", "Certificate.Name", foundCert.Name)
		// Spec updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func removePolicy(instance *operatorv1alpha1.AuditLogging, client client.Client, crName string) error {
	reqLogger := log.WithValues("func", "removeCR")
	// Get Audit Policy
	// Using a unstructured object.
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   res.AuditPolicyGroup,
		Kind:    res.AuditPolicyKind,
		Version: res.AuditPolicyVersion,
	})
	err := client.Get(context.Background(), types.NamespacedName{Name: crName, Namespace: instance.Namespace}, policy)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Error(err, "Error getting policy", "Name", crName)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), policy); err != nil {
			reqLogger.Error(err, "Error deleting policy", "Name", crName)
			return err
		}
	} else {
		return err
	}
	return nil
}

func removeCRD(client client.Client, crdName string) error {
	// Delete CustomResourceDefintion
	customResourceDefinition := &extv1beta1.CustomResourceDefinition{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: crdName, Namespace: ""},
		customResourceDefinition); err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Error getting custome resource definition", "msg", err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), customResourceDefinition); err != nil {
			log.V(1).Info("Error deleting custom resource definition", "name", crdName, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}
