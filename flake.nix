{
  description = "xnode-tpm-verify — minimal TPM2 attestation verifier service. Companion to johnforfar/xnode-tpm-attest.";

  inputs = {
    xnode-manager.url = "github:Openmesh-Network/xnode-manager";
    nixpkgs.follows = "xnode-manager/nixpkgs";
  };

  outputs = { self, nixpkgs, xnode-manager }: {

    nixosModules.default = ./nix/module.nix;

    nixosConfigurations.container = nixpkgs.lib.nixosSystem {
      modules = [
        xnode-manager.nixosModules.container
        {
          services.xnode-container.xnode-config = {
            host-platform = ./xnode-config/host-platform;
            state-version = ./xnode-config/state-version;
            hostname      = ./xnode-config/hostname;
          };
          networking.useDHCP = true;
          networking.dhcpcd.enable = true;
          systemd.services.dhcpcd.wantedBy = [ "multi-user.target" ];
          systemd.services.dhcpcd.enable = true;
        }
        ./nix/module.nix
      ];
    };
  };
}
