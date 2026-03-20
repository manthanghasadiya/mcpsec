{
  pkgs ? import <nixpkgs> { },
  withAi ? false,
  withRogue ? false,
  withExploit ? false,
  withAll ? false,
}:
let
  enableAi = withAi || withAll;
  enableRogue = withRogue || withAll;
  enableExploit = withExploit || withAll;
  extraPyPkgs = ps: with ps; 
    pkgs.lib.optionals enableAi [ openai ]
    ++ pkgs.lib.optionals enableRogue [ aiohttp ]
    ++ pkgs.lib.optionals enableExploit [ prompt-toolkit ];
  mcpsec = pkgs.python3Packages.buildPythonPackage {
    pname = "mcpsec";
    version = "2.6.1";
    pyproject = true;
    src = ./.;
    build-system = [ pkgs.python3Packages.hatchling ];
    
    postPatch = ''
      substituteInPlace pyproject.toml \
        --replace-fail 'hatchling>=1.21,<1.27' 'hatchling'
    '';
    dependencies = with pkgs.python3Packages; [
      mcp rich typer httpx pydantic anyio semgrep
    ] ++ (extraPyPkgs pkgs.python3Packages);
  };
  pythonEnv = pkgs.python3.withPackages (ps: [
    mcpsec
  ] ++ (extraPyPkgs ps));
in
pkgs.mkShell {
  packages = [ pythonEnv ];
  PATH="${pythonEnv}/bin:$PATH";
  PYTHONPATH="${pythonEnv}/${pythonEnv.sitePackages}";
}
