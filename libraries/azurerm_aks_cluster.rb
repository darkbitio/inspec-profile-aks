# frozen_string_literal: true

require 'azurerm_resource'

class AzurermAksCluster < AzurermSingularResource
  name 'azurerm_aks_cluster'
  desc 'Verifies settings for AKS Clusters'
  example <<-EXAMPLE
    describe azurerm_aks_cluster(resource_group: 'example', name: 'name') do
      its(name) { should eq 'name'}
    end
  EXAMPLE

  ATTRS = %i(
    name
    id
    etag
    type
    location
    tags
    properties
  ).freeze

  attr_reader(*ATTRS)

  def initialize(resource_group: nil, name: nil)
    resp = management.aks_cluster(resource_group, name)
    return if has_error?(resp)

    assign_fields(ATTRS, resp)

    @exists = true
  end

  def has_logging_enabled?
    return @properties[:addonProfiles][:omsagent][:enabled] if @properties.members.include?(:addonProfiles) && @properties[:addonProfiles].members.include?(:omsagent) && @properties[:addonProfiles][:omsagent].members.include?(:enabled)
    false
  end

  def has_network_policy_enabled?
    return !@properties[:networkProfile][:networkPolicy].nil? if @properties.members.include?(:networkProfile) && @properties[:networkProfile].members.include?(:networkPolicy)
    false
  end

  def api_server_access_ranges
    return @properties[:apiServerAccessProfile][:authorizedIPRanges] if @properties.members.include?(:apiServerAccessProfile) && @properties[:apiServerAccessProfile].members.include?(:authorizedIPRanges)
    return ["0.0.0.0/0"]
  end

  def has_public_api_authorized_ranges?
    ranges = []
    ranges.push(*api_server_access_ranges).include?("0.0.0.0/0")
  end

  def has_rbac_enabled?
    return @properties[:enableRBAC] if @properties.members.include?(:enableRBAC)
    false
  end

  def to_s
    "'#{name}' AKS Cluster"
  end
end
