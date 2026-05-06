{ config, lib, pkgs, ... }:
let
  serverPy = pkgs.runCommand "xnode-tpm-verify" { } ''
    install -Dm755 ${../server.py} $out/bin/xnode-tpm-verify
    sed -i "1c#!${pkgs.python3}/bin/python3" $out/bin/xnode-tpm-verify
  '';
in
{
  environment.systemPackages = [ pkgs.python3 serverPy ];

  systemd.tmpfiles.rules = [ "d /var/lib/xnode-tpm-verify 0755 root root -" ];

  systemd.services.xnode-tpm-verify = {
    description = "xnode-tpm-verify — TPM2 attestation verifier";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${serverPy}/bin/xnode-tpm-verify";
      Restart = "on-failure";
      RestartSec = "5s";
      StandardOutput = "journal";
      StandardError = "journal";
      Environment = [ "STATE_DIR=/var/lib/xnode-tpm-verify" "PORT=8080" ];
      User = "root";
    };
  };

  networking.firewall.allowedTCPPorts = [ 8080 ];
}
