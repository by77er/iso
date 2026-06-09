# System-level settings that make a NixOS rootfs boot cleanly under
# Firecracker as a microVM (no bootloader, virtio devices, serial console).
{ config
, lib
, pkgs
, modulesPath
, ...
}:
{
  imports = [
    # Keep the closure lean; Firecracker images want to be small.
    (modulesPath + "/profiles/minimal.nix")
  ];

  # Firecracker loads the kernel + initrd directly via its API. There is no
  # in-guest bootloader and no partition table.
  boot.loader.grub.enable = false;
  boot.loader.generic-extlinux-compatible.enable = false;

  # NixOS still *builds* an initrd as part of `toplevel` (we just never hand it
  # to Firecracker, see below). Its default module set includes storage/USB
  # drivers like `ahci` that no longer exist after the kernel strip, which
  # breaks the initrd's modules-shrunk build. We don't use the initrd, so drop
  # the default modules entirely; root (virtio-blk + ext4) is built into the
  # kernel anyway.
  boot.initrd.includeDefaultModules = false;

  # Boot WITHOUT an initrd: we build the root-path drivers (virtio transport +
  # virtio-blk + ext4) straight into the kernel, so it can mount /dev/vda and
  # exec stage-2 init directly — the same way a container boots.
  #
  # We deliberately do NOT set `boot.initrd.enable = false`: in nixpkgs that
  # path is only wired for containers, and a normal machine `toplevel` build
  # references `system.build.initialRamdisk` unconditionally (it would fail to
  # evaluate). So NixOS still *builds* an initrd as part of toplevel — we just
  # never hand it to Firecracker. Boot with:
  #   root=/dev/vda rootfstype=ext4 rw init=/nix/var/nix/profiles/system/init
  #
  # Trade-offs vs. using the initrd: custom kernel = local compile (no binary
  # cache), and no stage-1 features (autoResize, boot-time fsck).
  #
  # virtio_net must also be built in (not a module): the kernel `ip=` boot-param
  # autoconfiguration (IP_PNP) runs early in boot, before userspace loads any
  # modules, so eth0 has to exist at that point or the static IP is silently
  # dropped.
  # We intentionally disable whole kernel subsystems (USB, sound, DRM, ...)
  # below. NixOS's base/common kernel config still *requests* sub-options of
  # those subsystems (e.g. CONFIG_USB_HIDDEV), which then end up absent from
  # the generated .config. On x86 "pc" nixpkgs treats such "unused option"
  # requests as fatal, so relax that to a warning. boot.kernelPatches (set
  # below) is still layered on top by the boot.kernelPackages `apply` hook.
  boot.kernelPackages = lib.mkForce (
    pkgs.linuxPackages.extend (
      _self: super: {
        kernel = super.kernel.override { ignoreConfigErrors = true; };
      }
    )
  );

  boot.kernelPatches = [
    {
      name = "firecracker-builtin-rootfs-drivers";
      patch = null;
      # nixpkgs renamed this from `extraStructuredConfig` (unstable 2025+).
      structuredExtraConfig = with lib.kernel; {
        # ---- Root-path + net drivers built in (no initrd) ----
        VIRTIO = yes;
        VIRTIO_MENU = yes;
        VIRTIO_MMIO = yes; # Firecracker x86_64 transport (NOT pci)
        VIRTIO_BLK = yes;
        VIRTIO_NET = lib.mkForce yes;
        EXT4_FS = yes;
        # Kernel-level IP autoconfiguration so `ip=...` on the cmdline applies
        # (base config sets IP_PNP=n, so force it).
        IP_PNP = lib.mkForce yes;

        # ---- VM reset path ----
        # `reboot=k` (see boot.kernelParams) resets the VM by pulsing the
        # i8042 keyboard-controller reset line, so keep the i8042 serio + AT
        # keyboard driver even though the guest has no real input devices.
        # Killing INPUT/SERIO outright would break clean reboot/poweroff.
        SERIO = yes;
        SERIO_I8042 = yes;
        KEYBOARD_ATKBD = yes;

        # ================================================================
        # Strip hardware a Firecracker microVM physically cannot have.
        # mkForce overrides the NixOS defconfig; disabling a subsystem root
        # cascades to every driver beneath it. This shrinks the image and
        # cuts device-probe time at boot.
        #
        # NOTE: we are already on a local-compile path (any structured
        # config defeats the kernel binary cache), so this is "free".
        # ================================================================

        # No PCI bus in Firecracker x86_64 (transport is virtio-MMIO above).
        # If a future build breaks or the guest misbehaves, relax `PCI` back
        # to its default first.
        PCI = lib.mkForce no;
        VIRTIO_PCI = lib.mkForce no;

        # Serial console only (console=ttyS0) — no graphics stack.
        DRM = lib.mkForce no;
        FB = lib.mkForce no;
        AGP = lib.mkForce no;

        # No audio.
        SOUND = lib.mkForce no;
        SND = lib.mkForce no;

        # No USB / HID / pointer devices (AT keyboard above is kept for the
        # reset path only). Disable the HID_SUPPORT umbrella rather than the
        # HID core symbol, which is `select`ed by Surface HID and would loop.
        USB_SUPPORT = lib.mkForce no;
        HID_SUPPORT = lib.mkForce no;
        INPUT_MOUSEDEV = lib.mkForce no;
        INPUT_JOYSTICK = lib.mkForce no;
        INPUT_TABLET = lib.mkForce no;
        INPUT_TOUCHSCREEN = lib.mkForce no;

        # No wireless / bluetooth / cellular.
        WLAN = lib.mkForce no;
        WIRELESS = lib.mkForce no;
        BT = lib.mkForce no;
        WWAN = lib.mkForce no;

        # No x86 vendor "platform" devices (HP/Thinkpad/EeePC WMI, etc.).
        # This is the umbrella that `select`s HWMON/RFKILL/BACKLIGHT; killing
        # it lets the rest of the strip stick without kconfig select loops.
        X86_PLATFORM_DEVICES = lib.mkForce no;

        # No physical storage controllers (root = virtio-blk).
        ATA = lib.mkForce no; # SATA / AHCI / PATA
        SCSI = lib.mkForce no; # sd/sr/virtio-scsi — FC uses virtio-blk
        BLK_DEV_NVME = lib.mkForce no;
        MMC = lib.mkForce no;

        # No capture / TV hardware.
        MEDIA_SUPPORT = lib.mkForce no;

        # NOTE: HWMON / THERMAL / WATCHDOG / RFKILL are intentionally NOT
        # forced off — they are `select`ed by various drivers, and forcing
        # `n` on a selected symbol makes kconfig loop ("repeated question").
        # Disabling their selectors (PCI, DRM, X86_PLATFORM_DEVICES, WLAN/BT
        # above) is what actually drops them.

        # No laptop/desktop power management (the VM is always-on).
        SUSPEND = lib.mkForce no;
        HIBERNATION = lib.mkForce no;
        CPU_FREQ = lib.mkForce no;

        # Filesystems: keep ext4 (root, above) + overlayfs (Docker, below).
        # Drop everything else we never mount.
        XFS_FS = lib.mkForce no;
        BTRFS_FS = lib.mkForce no;
        F2FS_FS = lib.mkForce no;
        REISERFS_FS = lib.mkForce no;
        JFS_FS = lib.mkForce no;
        NTFS3_FS = lib.mkForce no;
        NFS_FS = lib.mkForce no;
        NFSD = lib.mkForce no;

        # ================================================================
        # KEEP for Docker (left at NixOS/Docker-module defaults; the strip
        # above does not touch them):
        #   netfilter / IP_NF_* / NF_NAT / NF_CONNTRACK, MACVLAN, cgroups +
        #   CGROUP_BPF, BPF_SYSCALL, and the NET/PID/USER/UTS/IPC namespaces.
        # We pin the few overlay/bridge/veth options explicitly so a stray
        # default flip can't silently break container networking + storage.
        # ================================================================
        OVERLAY_FS = yes;
        BRIDGE = yes;
        VETH = yes;
      };
    }
  ];

  # The serial port is your console into a Firecracker guest.
  # NOTE: the *effective* cmdline is set by the VMM (controld's per-VM boot
  # args), not these params, since we boot init= directly with no
  # bootloader. Kept here for intent/consistency.
  #
  # acpi=off: Firecracker >= ~1.5 describes devices/IRQs via ACPI, but this
  # stripped kernel's ACPI interpreter fails to load FC's tables ("Unable to
  # load the System Description Tables"), which breaks virtio-mmio IRQ routing
  # -> `virtio_blk/virtio_net: probe ... failed with error -22` -> no /dev/vda
  # -> root-mount panic. Disabling ACPI falls back to the MP-table + the
  # `virtio_mmio.device=` cmdline entries, and the guest boots. (flake.nix was
  # written against FC v1.7, which predates ACPI device discovery.)
  boot.kernelParams = [
    "console=ttyS0"
    "reboot=k"
    "panic=1"
    "acpi=off"
    "random.trust_cpu=on"
    # Fast boot: the serial console is the boot bottleneck (115200 baud), so cut
    # log chatter. The effective cmdline is set by controld; kept aligned here.
    "quiet"
    "loglevel=3"
  ];

  # ---- Fast-boot trims for a microVM -------------------------------------
  # A Firecracker guest has kvm-clock (no NTP drift), no real pstore, and agents
  # don't need docker started at boot (socket-activated on first use). Dropping
  # these takes the boot off the network-online + docker critical path.
  services.timesyncd.enable = false;
  virtualisation.docker.enableOnBoot = false;
  systemd.services.mount-pstore.enable = lib.mkForce false;
  # No guest firewall: the host's nft fabric is the isolation boundary
  # (per-tap anti-spoof source pin + VM-to-VM drop + broker-only egress), so an
  # in-guest firewall is redundant. Agents run as root in the VM anyway.
  networking.firewall.enable = false;
  # (systemd.network.wait-online is already disabled in the networking section.)

  # Root filesystem: the single virtio-blk device provisioned by
  # `iso provision-base`. No stage-1, so no autoResize/fsck here — the image is
  # sized at provision time.
  fileSystems."/" = {
    device = "/dev/vda";
    fsType = "ext4";
  };

  # Networking: Firecracker presents a virtio-net NIC as eth0. Rather than
  # running a DHCP client (which adds ~0.5-2s of non-deterministic boot
  # latency), the per-VM address is assigned by the kernel via the `ip=` boot
  # param set by the host control plane. iso uses a constant per-VM /31:
  #   ip=172.20.0.1::172.20.0.0:255.255.255.254::eth0:off
  # KeepConfiguration=yes tells networkd to preserve that kernel-assigned
  # address instead of flushing it.
  networking.useDHCP = false;
  networking.useNetworkd = true;
  networking.usePredictableInterfaceNames = false;
  systemd.network.enable = true;

  # The per-VM IPv4 address is assigned by the kernel `ip=` param *before*
  # userspace starts, so the network is already up by the time systemd runs.
  # systemd-networkd-wait-online, however, blocks until *networkd* completes a
  # configuration cycle it owns (a DHCP lease or an applied static `Address=`)
  # — which never happens here (DHCP=no, no Address=, only KeepConfiguration=
  # adopting the kernel address). It therefore sits until its 120s timeout,
  # and since docker.service is ordered After network-online.target, that
  # ~2-minute stall lands squarely on the critical boot path. There is nothing
  # to wait for, so disable it; network-online.target is then reached promptly.
  systemd.network.wait-online.enable = false;

  systemd.network.networks."10-eth0" = {
    matchConfig.Name = "eth0";
    networkConfig.DHCP = "no";
    networkConfig.KeepConfiguration = "yes";
    linkConfig.RequiredForOnline = "no";
  };

  # The kernel `ip=` param doesn't populate a resolver, so bake one in: iso's
  # control plane serves DNS on the services dummy address.
  # `metadata.iso.internal` resolves here (the `.internal` TLD avoids the
  # `.local` mDNS reservation, so systemd-resolved sends it to this unicast
  # server rather than multicast).
  networking.nameservers = [
    "172.22.0.1"
  ];

  # Autologin root on the serial console for debugging. Lock this down for
  # anything facing untrusted code.
  services.getty.autologinUser = lib.mkDefault "root";

  # Trim the image.
  documentation.enable = false;
  documentation.nixos.enable = false;
  documentation.man.enable = false;

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  system.stateVersion = "24.11";
}
