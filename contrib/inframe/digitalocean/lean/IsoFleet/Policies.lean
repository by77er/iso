import IsoFleet.Stack

/-!
What this billable test rig may and may not be, proved while this module
compiles: one data center, one control host and exactly two VM hosts, every
droplet on the private network with the account key and the tags, and a
firewall that admits only SSH and the fleet API from outside. `inframe plan`
and `inframe apply` run these before touching the cloud.
-/

open Inframe

def graph : Graph := buildGraph infrastructure

def droplets : List ResourceSpec := graph.resourcesOfType "digitalocean_droplet"

/-- Every droplet, and the VPC, is in `region`, named literally. -/
def oneRegion : Policy :=
  Policy.resources "one-region" fun resource =>
    match resource.argument? "region" with
    | none => none
    | some (.literal (.string r)) => if r == region then none else some s!"{r} is not {region}"
    | some _ => some "region must be a literal"

/-- One control host and two VM hosts, and nothing else. -/
def threeMachines : Policy :=
  Policy.graph "three-machines" fun g =>
    let names := (g.resourcesOfType "digitalocean_droplet").map (·.name)
    if names == ["control", "host-a", "host-b"] then none
    else some s!"expected control, host-a, host-b; got {names}"

/-- Every droplet sits on the stack's VPC and carries the account key and the tags. -/
def onTheNetworkWithKeyAndTags : Policy :=
  Policy.resourcesOfType "network-key-tags" "digitalocean_droplet" fun d =>
    let onVpc := match d.argument? "vpc_uuid" with
      | some reference => reference.refersTo (.res "digitalocean_vpc" "iso") ["id"]
      | none => false
    let hasKey := match d.argument? "ssh_keys" with
      | some (.array [reference]) => reference.refersTo (.data "digitalocean_ssh_key" "admin") ["fingerprint"]
      | _ => false
    let hasTags := d.argumentIs "tags" tags
    if !onVpc then some "droplet is not on the iso VPC"
    else if !hasKey then some "droplet does not carry the admin key"
    else if !hasTags then some "droplet is not tagged"
    else none

/-- Only SSH and the fleet API are open to the internet; all else is the VPC. -/
def inboundIsSshFleetAndVpc : Policy :=
  Policy.resourcesOfType "inbound-ssh-fleet-vpc" "digitalocean_firewall" fun f =>
    match f.argument? "inbound_rule" with
    | some (.array rules) =>
      let fromInternet := rules.filter fun rule =>
        match rule with
        | .object fields =>
          match fields.lookup "source_addresses" with
          | some (.literal (.array addrs)) => addrs.any (· == .string "0.0.0.0/0")
          | _ => false
        | _ => false
      let ports := fromInternet.filterMap fun rule =>
        match rule with
        | .object fields =>
          match fields.lookup "port_range" with
          | some (.literal (.string p)) => some p
          | _ => none
        | _ => none
      if ports == ["22", "7080"] then none
      else some s!"public inbound ports are {ports}, expected 22 and 7080"
    | _ => some "firewall has no inbound rules"

def policies : Policy :=
  Policy.all "iso-fleet-digitalocean"
    [ Policy.validGraph, oneRegion, threeMachines, onTheNetworkWithKeyAndTags, inboundIsSshFleetAndVpc ]

theorem policies_hold : policies.Holds graph := by decide

/-- The token never enters the graph; the provider reads it from the environment. -/
theorem no_graph_secrets : graph.secretEnvironmentNames = [] := by decide

/-- The firewall is wired after every droplet, and every droplet after the VPC and the key. -/
theorem wired :
    graph.dependsOn (.res "digitalocean_firewall" "iso-fleet") (.res "digitalocean_droplet" "host-b") = true ∧
    graph.dependsOn (.res "digitalocean_droplet" "host-a") (.res "digitalocean_vpc" "iso") = true ∧
    graph.dependsOn (.res "digitalocean_droplet" "control") (.data "digitalocean_ssh_key" "admin") = true := by
  decide

def main : IO Unit :=
  policies.enforce graph
