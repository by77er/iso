import Inframe
import DigitalOcean.Data.SshKey
import DigitalOcean.Resource.Droplet
import DigitalOcean.Resource.Firewall
import DigitalOcean.Resource.Vpc

/-!
iso, distributed, on DigitalOcean: one control host and two VM hosts on a
private network in one data center.

- `control` runs everything that is not a VM host: `iso-fleetd` (the one API
  clients talk to), the proxy tier (`iso-proxyd --role proxy`), the CA
  (`iso-cad`) and the secrets service (`iso-secretsd`). It holds the leaf
  keys and the secret values; the VM hosts never do.
- `host-a` and `host-b` run `iso-controld` and the proxy edge
  (`iso-proxyd --role edge`), and need KVM. DigitalOcean droplets expose
  nested virtualization in every region but do not recommend it, so expect
  slow guests; this is a test rig, not a place to run a fleet for real.

The graph only provisions machines, a network, a firewall and cloud-init that
prepares the OS. `../deploy.sh` then installs iso on them from your build.
The account's SSH key is read by name (`adminKeyName`), never created here.
-/

open Inframe
open DigitalOcean
open DigitalOcean.Resource

/-- The name of the SSH key in your DigitalOcean account. Edit before use. -/
def adminKeyName : String := "Desktop Nu"

def region : String := "nyc3"
def image : String := "ubuntu-24-04-x64"
/-- Everything this stack creates carries these, so it is easy to find and
easy to sweep. -/
def tags : List String := ["iso", "iso-fleet-test"]

/-- The private network. Every service the hosts and the control host speak
to each other listens on their addresses in it, never on the public side. -/
def vpcRange : String := "10.120.0.0/20"
def anywhere : List String := ["0.0.0.0/0", "::/0"]

/-- The control host needs no KVM: a small shared-CPU droplet. -/
def controlSize : String := "s-2vcpu-4gb"
/-- A VM host runs microVMs under nested KVM; give it memory and cores. -/
def hostSize : String := "s-4vcpu-8gb"

/-- cloud-init for the control host: nothing iso-specific, only what
`deploy.sh` expects to find. A plain literal, so the policies can still be
proved by `decide` over the whole graph. -/
def controlUserData : String :=
  "#cloud-config\n" ++
  "package_update: true\n" ++
  "packages: [curl, jq, rsync, ca-certificates]\n" ++
  "runcmd:\n" ++
  "  - mkdir -p /var/lib/iso /var/lib/iso-fleet /etc/iso-fleet /opt/iso\n" ++
  "  - touch /var/lib/iso/.cloud-init-done\n"

/-- cloud-init for a VM host: the packages controld shells out to, the
Firecracker release binaries, IP forwarding, and a loud marker if the
droplet has no /dev/kvm. -/
def hostUserData : String :=
  "#cloud-config\n" ++
  "package_update: true\n" ++
  "packages: [lvm2, thin-provisioning-tools, mmdebstrap, nftables, curl, jq, rsync, ca-certificates, xz-utils]\n" ++
  "write_files:\n" ++
  "  - path: /etc/sysctl.d/90-iso.conf\n" ++
  "    content: |\n" ++
  "      net.ipv4.ip_forward = 1\n" ++
  "runcmd:\n" ++
  "  - sysctl --system\n" ++
  "  - modprobe kvm_intel || modprobe kvm_amd || true\n" ++
  "  - test -c /dev/kvm || touch /var/lib/iso-no-kvm\n" ++
  "  - modprobe dm_thin_pool || true\n" ++
  "  - mkdir -p /var/lib/iso /etc/iso /opt/iso\n" ++
  "  - cd /tmp && curl -sSfL -o fc.tgz https://github.com/firecracker-microvm/firecracker/releases/download/v1.16.0/firecracker-v1.16.0-x86_64.tgz && tar xzf fc.tgz && install -m755 release-v1.16.0-x86_64/firecracker-v1.16.0-x86_64 /usr/local/bin/firecracker && install -m755 release-v1.16.0-x86_64/jailer-v1.16.0-x86_64 /usr/local/bin/jailer\n" ++
  "  - touch /var/lib/iso/.cloud-init-done\n"

structure Rig where
  network : Vpc.Vpc
  control : Droplet.Droplet
  hostA : Droplet.Droplet
  hostB : Droplet.Droplet

def droplet (name : String) (size userData : String) (network : Vpc.Vpc)
    (key : Data.SshKey.SshKey) (valid : validIdentifier name = true := by valid_identifier) :
    Infra Droplet.Droplet :=
  Droplet.create name
    { image := image
      name := "iso-" ++ name
      size := size
      region := region
      vpcUuid := network.id
      sshKeys := array [key.fingerprint]
      userData := userData
      monitoring := true
      tags := tags }
    valid

/-- SSH and the fleet API (mutual TLS) from anywhere; everything between the
machines on the private network; everything out. -/
def firewall (droplets : List Droplet.Droplet) : Infra Firewall.Firewall :=
  Firewall.create "iso-fleet"
    { name := "iso-fleet"
      dropletIds := array (droplets.map (·.id.tonumber))
      inboundRule :=
        [ { protocol := "tcp", portRange := "22", sourceAddresses := anywhere }
        , { protocol := "tcp", portRange := "7080", sourceAddresses := anywhere }
        , { protocol := "tcp", portRange := "1-65535", sourceAddresses := [vpcRange] }
        , { protocol := "udp", portRange := "1-65535", sourceAddresses := [vpcRange] }
        , { protocol := "icmp", sourceAddresses := [vpcRange] } ]
      outboundRule :=
        [ { protocol := "tcp", portRange := "1-65535", destinationAddresses := anywhere }
        , { protocol := "udp", portRange := "1-65535", destinationAddresses := anywhere }
        , { protocol := "icmp", destinationAddresses := anywhere } ] }

def rig : Infra Rig := do
  let key ← Data.SshKey.read "admin" { name := adminKeyName }
  let network ← Vpc.create "iso" { name := "iso-fleet", region := region, ipRange := vpcRange }
  let control ← droplet "control" controlSize controlUserData network key
  let hostA ← droplet "host-a" hostSize hostUserData network key
  let hostB ← droplet "host-b" hostSize hostUserData network key
  let _ ← firewall [control, hostA, hostB]
  pure { network, control, hostA, hostB }

/-- The default provider is lazy: every constructor embeds its provider pin,
and the provider reads `DIGITALOCEAN_TOKEN` from the environment at execution
time. -/
def infrastructure : Infra Unit := do
  let r ← rig
  output "control_ip" r.control.ipv4Address
  output "control_private_ip" r.control.ipv4AddressPrivate
  output "host_ips" (object [("a", r.hostA.ipv4Address), ("b", r.hostB.ipv4Address)])
  output "host_private_ips" (object [("a", r.hostA.ipv4AddressPrivate), ("b", r.hostB.ipv4AddressPrivate)])
  output "vpc_range" r.network.ipRange
