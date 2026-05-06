{ config, lib, pkgs, ... }:
let
  serverPy = pkgs.runCommand "xnode-tpm-verify" { } ''
    install -Dm755 ${../server.py} $out/bin/xnode-tpm-verify
    sed -i "1c#!${pkgs.python3}/bin/python3" $out/bin/xnode-tpm-verify
  '';
  # openssl is shelled out to for AK signature verification on quotes.
  pathDir = pkgs.symlinkJoin {
    name = "xnode-tpm-verify-runtime";
    paths = [ pkgs.openssl pkgs.coreutils ];
  };
in
{
  environment.systemPackages = [ pkgs.python3 serverPy pkgs.openssl ];

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
      Environment = [
        "STATE_DIR=/var/lib/xnode-tpm-verify"
        "PORT=8080"
        "PATH=${pathDir}/bin"
      ];
      EnvironmentFile = "-/run/secrets/xnode-tpm-verify.env";
      User = "root";
    };
  };

  networking.firewall.allowedTCPPorts = [ 8080 ];
}
