# The custom Firecracker kernel config (builtin virtio/ext4/IP_PNP + a hardware
# strip). Built with the PINNED `nixpkgs-kernel` (see flake.nix): newer nixpkgs
# changed kconfig generation in a way that breaks this `ignoreConfigErrors` +
# structuredExtraConfig path, so we keep the kernel on a known-good nixpkgs and
# take userspace from a current one. The built kernel is then handed to the
# (current-nixpkgs) rootfs system via `boot.kernelPackages`.
{ lib, pkgs, ... }:
{
  # Relax "unused option" requests to a warning — we disable whole subsystems
  # whose sub-options the NixOS base config still requests.
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
      extraStructuredConfig = with lib.kernel; {
        # ---- Root-path + net drivers built in (no initrd) ----
        VIRTIO = yes;
        VIRTIO_MENU = yes;
        VIRTIO_MMIO = yes; # Firecracker x86_64 transport (NOT pci)
        VIRTIO_BLK = yes;
        VIRTIO_NET = lib.mkForce yes;
        EXT4_FS = yes;
        IP_PNP = lib.mkForce yes;

        # ---- vsock: the host reaches the guest agent through it ----
        VSOCKETS = yes;
        VIRTIO_VSOCKETS = yes;
        VIRTIO_VSOCKETS_COMMON = yes;

        # ---- VM reset path (reboot=k pulses i8042) ----
        SERIO = yes;
        SERIO_I8042 = yes;
        KEYBOARD_ATKBD = yes;

        # ---- Strip hardware a Firecracker microVM cannot have ----
        PCI = lib.mkForce no;
        VIRTIO_PCI = lib.mkForce no;
        DRM = lib.mkForce no;
        FB = lib.mkForce no;
        AGP = lib.mkForce no;
        SOUND = lib.mkForce no;
        SND = lib.mkForce no;
        USB_SUPPORT = lib.mkForce no;
        HID_SUPPORT = lib.mkForce no;
        INPUT_MOUSEDEV = lib.mkForce no;
        INPUT_JOYSTICK = lib.mkForce no;
        INPUT_TABLET = lib.mkForce no;
        INPUT_TOUCHSCREEN = lib.mkForce no;
        WLAN = lib.mkForce no;
        WIRELESS = lib.mkForce no;
        BT = lib.mkForce no;
        WWAN = lib.mkForce no;
        X86_PLATFORM_DEVICES = lib.mkForce no;
        ATA = lib.mkForce no;
        SCSI = lib.mkForce no;
        BLK_DEV_NVME = lib.mkForce no;
        MMC = lib.mkForce no;
        MEDIA_SUPPORT = lib.mkForce no;
        SUSPEND = lib.mkForce no;
        HIBERNATION = lib.mkForce no;
        CPU_FREQ = lib.mkForce no;
        XFS_FS = lib.mkForce no;
        BTRFS_FS = lib.mkForce no;
        F2FS_FS = lib.mkForce no;
        REISERFS_FS = lib.mkForce no;
        JFS_FS = lib.mkForce no;
        NTFS3_FS = lib.mkForce no;
        NFS_FS = lib.mkForce no;
        NFSD = lib.mkForce no;

        # ---- Keep for Docker (overlay/bridge/veth) ----
        OVERLAY_FS = yes;
        BRIDGE = yes;
        VETH = yes;
      };
    }
  ];
}
