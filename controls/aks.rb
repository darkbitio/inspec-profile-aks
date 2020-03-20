# Copyright 2020 Darkbit.io
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

title 'Evaluate AKS Cluster Configuration Best Practices'

resourcegroup = attribute('resourcegroup')
clustername = attribute('clustername')

control "aks-1" do
  impact 0.9

  title "Ensure logging to Azure Monitor is configured"
  desc "Azure Monitor for containers collects memory and processor metrics from controllers, nodes, and containers that are available in Kubernetes through the Metrics API. Container logs are also collected. Metrics are written to the metrics store and log data is written to the logs store associated with an Log Analytics workspace.  To ensure more complete visibility of activity inside an AKS cluster, this setting should be enabled."
  desc "remediation", "Use the CLI or Terraform to enable the Azure Monitor addon.  This can be performed on new or existing clusters."
  desc "validation", "Run `az aks show -g <resourceGroupofAKSCluster> -n <nameofAksCluster>` and confirm that `addonProfiles > omsagent > enabled` is true.  Or, via kubectl, run `kubectl get ds omsagent --namespace=kube-system` and `kubectl get deployment omsagent-rs -n=kube-system` and confirm the pods are healthy."

  tag platform: "Azure"
  tag category: "Management and Governance"
  tag resource: "AKS"
  tag effort: 0.2

  ref "Enable on new AKS cluster", url: "https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-enable-new-cluster"
  ref "Enable on existing AKS cluster", url: "https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-enable-existing-clusters"
  ref "Enable AKS Addons", url: "https://docs.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-enable-addons"
  ref "Azure Security", url: "https://docs.microsoft.com/en-us/azure/aks/concepts-security"

  describe "#{resourcegroup}/#{clustername}:" do
    subject { azurerm_aks_cluster(resource_group: resourcegroup, name: clustername) }
    it { should have_logging_enabled }
  end
end

control "aks-2" do
  impact 1.0

  title "Ensure RBAC is enabled"
  desc "In Kubernetes, the primary method of authorization is Role-Based Access Control (RBAC), and it should be enabled in all clusters to be able to regulate differentiated access to Kubernetes API resources to users and groups.  In AKS, this setting is enabled by default but can be overridden and disabled.  Any authenticated user, including pods running in the cluster with a service account mounted, have full control over the cluster, the compute resources, the applications, and data inside the cluster if RBAC is not enabled."
  desc "remediation", "Recreate the AKS cluster with `--enable-rbac=true` and ensure that all applications inside the cluster have appropriate Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings for their access to the API Server."
  desc "validation", "Run `az aks show -g <resourceGroupofAKSCluster> -n <nameofAksCluster>` and confirm the output shows that RBAC is enabled."

  tag platform: "Azure"
  tag category: "Identity and Access Management"
  tag resource: "AKS"
  tag effort: 1.0

  ref "AKS CLI Options", url: "https://docs.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-create"
  ref "Kubernetes RBAC", url: "https://kubernetes.io/docs/reference/access-authn-authz/authorization/"
  ref "Azure Security", url: "https://docs.microsoft.com/en-us/azure/aks/concepts-security"

  describe "#{resourcegroup}/#{clustername}:" do
    subject { azurerm_aks_cluster(resource_group: resourcegroup, name: clustername) }
    it { should have_rbac_enabled }
  end
end

control "aks-3" do
  impact 0.8

  title "Ensure API Server Authorized IP Ranges are configured"
  desc "By default, the AKS Kubernetes API server is available on a public IP address with an access control list that allows any IP address (0.0.0.0/0) to connect.  While this makes administration convenient, the scope of potential attackers is not limited should a newly discovered vulnerability or denial-of-service become available.  Also, should valid credentials from a phished administrator/developer be stolen or leaked, they can be directly used without having to originate from a known set of IP ranges." 
  desc "remediation", "Develop a remote cluster access strategy that funnels administrative access through a known subset of IP addresses or ranges, and configure the Authorized IP Ranges to include only those IPs and/or ranges.  Use `az aks create` or `az aks update` to set or update the `--api-server-authorized-ip-ranges` flag with a comma separated list of IPs/ranges. Optionally, enable `--enable-private-cluster` to prevent the API server from receiving a public IP address."
  desc "validation", "Run `az aks show -g <resourceGroupofAKSCluster> -n <nameofAksCluster>` and confirm the output shows that the authorized IP ranges do not include 0.0.0.0/0."

  tag platform: "Azure"
  tag category: "Network Access Control"
  tag resource: "AKS"
  tag effort: 0.5

  ref "AKS Authorized IP Ranges", url: "https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges"
  ref "AKS CLI Options", url: "https://docs.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-create"
  ref "AKS CLI Options", url: "https://docs.microsoft.com/en-us/cli/azure/aks?view=azure-cli-latest#az-aks-update"
  ref "Azure Security", url: "https://docs.microsoft.com/en-us/azure/aks/concepts-security"

  describe "#{resourcegroup}/#{clustername}:" do
    subject { azurerm_aks_cluster(resource_group: resourcegroup, name: clustername) }
    it { should_not have_public_api_authorized_ranges }
  end
end

control "aks-4" do
  impact 0.8

  title "Ensure Network policy is enabled"
  desc "By default, all Kubernetes pods inside a cluster can communicate with each other--even across namespaces.  All production Kubernetes clusters should have support enabled for being able to define Layer 4 `NetworkPolicy` resources, and in many cases, this is an optional addon that must be explicitly enabled.  With this support enabled, it's possible to define policies inside the cluster that restrict inbound and outbound network traffic to pods within namespaces and provide micro-segmentation.  Should a pod become compromised, strict `NetworkPolicy` configurations can significantly limit the attacker's ability to move laterally via the network."
  desc "remediation", "During AKS cluster creation, specify `--network-plugin azure` and `--network-policy azure` (or `--network-policy calico`).  This cannot be updated on running clusters."
  desc "validation", "Run `az aks show -g <resourceGroupofAKSCluster> -n <nameofAksCluster>` and confirm the output shows that the `network-policy` setting is set to `azure` or `calico`."

  tag platform: "Azure"
  tag category: "Network Access Control"
  tag resource: "AKS"
  tag effort: 0.9

  ref "AKS Network Policies", url: "https://docs.microsoft.com/en-us/azure/aks/use-network-policies"
  ref "Network Policy", url: "https://kubernetes.io/docs/concepts/services-networking/network-policies/#the-networkpolicy-resource"
  ref "Azure Security", url: "https://docs.microsoft.com/en-us/azure/aks/concepts-security"

  describe "#{resourcegroup}/#{clustername}:" do
    subject { azurerm_aks_cluster(resource_group: resourcegroup, name: clustername) }
    it { should have_network_policy_enabled }
  end
end
