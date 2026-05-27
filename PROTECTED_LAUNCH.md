# Protected App Launch

Protected launch is target scoped. It does not make the whole host PC appear virtual, and it does not spoof host disk, SMBIOS, TPM, GPU, monitor, MAC, or registry identifiers.

## Modes

- `sandbox`: Creates a per-target Windows Sandbox config. The target parent folder and session folder are mapped read-only, networking and vGPU are disabled, and the target opens inside Sandbox. Installed host apps under system locations are rejected because they cannot be safely moved into the Sandbox by mapping Program Files.
- `user`: Known browsers launch with session-local profiles. Non-browser targets launch on the host only after a warning is recorded because host hardware identifiers remain visible.
- `policy`: Requires Administrator, adds a reversible outbound Windows Firewall block for the exact target executable, then launches the target on the host with a recorded warning that local hardware identifiers remain visible.

## Artifacts

Each launch creates:

- `launches/<timestamp>/launch_plan.json`
- `launches/<timestamp>/launch.cmd`
- `launches/<timestamp>/protected_launch.wsb` for Sandbox launches
- `launches/<timestamp>/policy_rules.json` for policy launches

The session `snapshot.json` gets a `launchHistory` entry. Policy launches also append to `policyRules` so restore can delete active firewall rules. `session_manifest.json` is refreshed with hashes for launch artifacts.

## Boundaries

Protected launch uses blocking, isolation, and virtualization. It permanently excludes kernel hooks, third-party driver stack attachment, completion routine rewriting, dispatch patching, object patching, PDB offset parsing, mappers, and hardware response forgery.
