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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func (r *ReconcileAuditLogging) reconcileServiceAccount(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("cr.Name", instance.Name)
	expectedRes := res.BuildServiceAccount(instance)
	// Set CR instance as the owner and controller
	err := controllerutil.SetControllerReference(instance, expectedRes, r.scheme)
	if err != nil {
		reqLogger.Error(err, "Failed to define expected resource")
		return reconcile.Result{}, err
	}

	// If ServiceAccount does not exist, create it and requeue
	foundSvcAcct := &corev1.ServiceAccount{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: expectedRes.Name, Namespace: instance.Namespace}, foundSvcAcct)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a new ServiceAccount", "Namespace", instance.Namespace, "Name", expectedRes.Name)
		err = r.client.Create(context.TODO(), expectedRes)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new ServiceAccount", "Namespace", instance.Namespace, "Name", expectedRes.Name)
			return reconcile.Result{}, err
		}
		// Created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ServiceAccount")
		return reconcile.Result{}, err
	}
	// No extra validation of the service account required

	// No reconcile was necessary
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) checkOldServiceAccounts(instance *operatorv1alpha1.AuditLogging) {
	reqLogger := log.WithValues("func", "checkOldServiceAccounts", "instance.Name", instance.Name)
	fluentdSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      res.FluentdDaemonSetName + "-svcacct",
			Namespace: instance.Namespace,
		},
	}
	// check if the service account exists
	err := r.client.Get(context.TODO(),
		types.NamespacedName{Name: res.FluentdDaemonSetName + "-svcacct", Namespace: instance.Namespace}, fluentdSA)
	if err == nil {
		// found service account so delete it
		err := r.client.Delete(context.TODO(), fluentdSA)
		if err != nil {
			reqLogger.Error(err, "Failed to delete old fluentd service account")
		} else {
			reqLogger.Info("Deleted old fluentd service account")
		}
	} else if !errors.IsNotFound(err) {
		// if err is NotFound do nothing, else print an error msg
		reqLogger.Error(err, "Failed to get old fluentd service account")
	}

	policySA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      res.AuditPolicyControllerDeploy + "-svcacct",
			Namespace: instance.Namespace,
		},
	}
	// check if the service account exists
	err = r.client.Get(context.TODO(),
		types.NamespacedName{Name: res.AuditPolicyControllerDeploy + "-svcacct", Namespace: instance.Namespace}, policySA)
	if err == nil {
		// found service account so delete it
		err := r.client.Delete(context.TODO(), policySA)
		if err != nil {
			reqLogger.Error(err, "Failed to delete old policy controller service account")
		} else {
			reqLogger.Info("Deleted old policy controller service account")
		}
	} else if !errors.IsNotFound(err) {
		// if err is NotFound do nothing, else print an error msg
		reqLogger.Error(err, "Failed to get old policy controller service account")
	}
}

func (r *ReconcileAuditLogging) reconcileClusterRole(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("ClusterRole.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected := res.BuildClusterRole(instance)
	found := &rbacv1.ClusterRole{}
	// Note: clusterroles are cluster-scoped, so this does not search using namespace (unlike other resources above)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: ""}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new ClusterRole
		reqLogger.Info("Creating a new ClusterRole", "ClusterRole.Namespace", expected.Namespace, "ClusterRole.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new ClusterRole", "ClusterRole.Namespace", expected.Namespace,
				"ClusterRole.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// ClusterRole created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRole")
		return reconcile.Result{}, err
	} else if result := res.EqualClusterRoles(expected, found); result {
		// If role permissions are incorrect, update it and requeue
		reqLogger.Info("Found role is incorrect", "Found", found.Rules, "Expected", expected.Rules)
		found.Rules = expected.Rules
		err = r.client.Update(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to update role", "Name", found.Name)
			return reconcile.Result{}, err
		}
		reqLogger.Info("Updating ClusterRole", "ClusterRole.Name", found.Name)
		// Updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileClusterRoleBinding(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("ClusterRoleBinding.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected := res.BuildClusterRoleBinding(instance)
	found := &rbacv1.ClusterRoleBinding{}
	// Note: clusterroles are cluster-scoped, so this does not search using namespace (unlike other resources above)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: ""}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new Role
		reqLogger.Info("Creating a new ClusterRoleBinding", "ClusterRole.Namespace", expected.Namespace, "ClusterRoleBinding.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new ClusterRoleBinding", "ClusterRoleBinding.Namespace", expected.Namespace,
				"RoleBinding.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// ClusterRoleBinding created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get ClusterRoleBinding")
		return reconcile.Result{}, err
	} else if result := res.EqualClusterRoleBindings(expected, found); result {
		// If rolebinding is incorrect, delete it and requeue
		reqLogger.Info("Found rolebinding is incorrect", "Found", found.Subjects, "Expected", expected.Subjects)
		err = r.client.Delete(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete rolebinding", "Name", found.Name)
			return reconcile.Result{}, err
		}
		// Deleted - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileRole(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("Role.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected := res.BuildRole(instance)
	found := &rbacv1.Role{}
	// Note: clusterroles are cluster-scoped, so this does not search using namespace (unlike other resources above)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new Role
		// newClusterRole := res.BuildRole(instance)
		if err := controllerutil.SetControllerReference(instance, expected, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new Role", "Role.Namespace", expected.Namespace, "Role.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			reqLogger.Info("Already exists", "Role.Namespace", expected.Namespace, "Role.Name", expected.Name)
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new Role", "Role.Namespace", expected.Namespace,
				"Role.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// Role created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get Role")
		return reconcile.Result{}, err
	} else if result := res.EqualRoles(expected, found); result {
		// If role permissions are incorrect, update it and requeue
		reqLogger.Info("Found role is incorrect", "Found", found.Rules, "Expected", expected.Rules)
		found.Rules = expected.Rules
		err = r.client.Update(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to update role", "Name", found.Name)
			return reconcile.Result{}, err
		}
		reqLogger.Info("Updating Role", "Role.Name", found.Name)
		// Updated - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileAuditLogging) reconcileRoleBinding(instance *operatorv1alpha1.AuditLogging) (reconcile.Result, error) {
	reqLogger := log.WithValues("RoleBinding.Namespace", instance.Namespace, "instance.Name", instance.Name)
	expected := res.BuildRoleBinding(instance)
	found := &rbacv1.RoleBinding{}
	// Note: clusterroles are cluster-scoped, so this does not search using namespace (unlike other resources above)
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: expected.Name, Namespace: instance.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		// Define a new Role
		if err := controllerutil.SetControllerReference(instance, expected, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Creating a new RoleBinding", "Role.Namespace", expected.Namespace, "RoleBinding.Name", expected.Name)
		err = r.client.Create(context.TODO(), expected)
		if err != nil && errors.IsAlreadyExists(err) {
			// Already exists from previous reconcile, requeue.
			return reconcile.Result{Requeue: true}, nil
		} else if err != nil {
			reqLogger.Error(err, "Failed to create new RoleBinding", "RoleBinding.Namespace", expected.Namespace,
				"RoleBinding.Name", expected.Name)
			return reconcile.Result{}, err
		}
		// RoleBinding created successfully - return and requeue
		return reconcile.Result{Requeue: true}, nil
	} else if err != nil {
		reqLogger.Error(err, "Failed to get RoleBinding")
		return reconcile.Result{}, err
	} else if result := res.EqualRoleBindings(expected, found); result {
		// If rolebinding is incorrect, delete it and requeue
		reqLogger.Info("Found rolebinding is incorrect", "Found", found.Subjects, "Expected", expected.Subjects)
		err = r.client.Delete(context.TODO(), found)
		if err != nil {
			reqLogger.Error(err, "Failed to delete rolebinding", "Name", found.Name)
			return reconcile.Result{}, err
		}
		// Deleted - return and requeue
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func removeCR(client client.Client, crName string) error {
	// Delete Clusterrole
	clusterRole := &rbacv1.ClusterRole{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: crName, Namespace: ""}, clusterRole); err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Error getting cluster role", crName, err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), clusterRole); err != nil {
			log.V(1).Info("Error deleting cluster role", "name", crName, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}

func removeCRB(client client.Client, crbName string) error {
	// Delete ClusterRoleBinding
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{}
	if err := client.Get(context.Background(), types.NamespacedName{Name: crbName, Namespace: ""}, clusterRoleBinding); err != nil && errors.IsNotFound(err) {
		log.V(1).Info("Error getting cluster role binding", crbName, err)
		return nil
	} else if err == nil {
		if err = client.Delete(context.Background(), clusterRoleBinding); err != nil {
			log.V(1).Info("Error deleting cluster role binding", "name", crbName, "error message", err)
			return err
		}
	} else {
		return err
	}
	return nil
}
