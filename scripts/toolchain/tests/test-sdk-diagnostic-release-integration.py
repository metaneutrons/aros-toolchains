#!/usr/bin/env python3
"""Exercise the selected diagnostic ID through the pinned native SDK index CLI."""
import importlib.util
from pathlib import Path
import subprocess
import sys


def main():
    tools = Path(sys.argv[1]).resolve(strict=True)
    fixture_path = Path(__file__).with_name('test-compiler-sdk-route-v2.py')
    spec = importlib.util.spec_from_file_location('route_fixture', fixture_path)
    route = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(route)
    fixture = route.RouteFixture()
    try:
        fixture.event = 'workflow_dispatch'
        fixture.ref_type = 'branch'
        fixture.source_ref = 'refs/heads/feature/diagnostic'
        fixture.mode = 'qualify-v2-full'
        fixture.scope = 'full'
        result = fixture.run()
        if result.returncode:
            raise RuntimeError(result.stderr)
        release_id = fixture.outputs()['release_id']
        assert release_id == f'v0.0.0-dev.sha{fixture.producer_commit[:12]}'
    finally:
        fixture.close()

    # This is an isolated test checkout of the exact pinned tools commit. Change
    # only its fixture constants so its real CLI measures a package with the
    # producer's selected ID. Restore the source even if cargo fails.
    test = tools / 'crates/aros-cli/tests/toolchain_index_v2_cli.rs'
    original = test.read_text()
    old_id = 'const SDK_RELEASE_ID: &str = "v2.0.0";'
    old_url = 'const SDK_BASE_URL: &str = "https://example.invalid/aros/releases/v2.0.0";'
    assert original.count(old_id) == original.count(old_url) == 1
    revised = original.replace(old_id, f'const SDK_RELEASE_ID: &str = "{release_id}";')
    revised = revised.replace(old_url, f'const SDK_BASE_URL: &str = "https://example.invalid/aros/releases/{release_id}";')
    try:
        test.write_text(revised)
        subprocess.run(['cargo', 'test', '--locked', '-p', 'aros-cli', '--test',
                        'toolchain_index_v2_cli',
                        'family_v2_sdk_index_cli_binds_package_identity_and_independent_measurements',
                        '--', '--exact'], cwd=tools, check=True)
    finally:
        test.write_text(original)


if __name__ == '__main__':
    main()
