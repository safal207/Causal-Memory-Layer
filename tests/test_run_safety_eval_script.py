from pathlib import Path
import subprocess
import sys


def test_run_safety_eval_script_writes_markdown(tmp_path: Path) -> None:
    output = tmp_path / 'RESULTS.md'
    result = subprocess.run(
        [
            sys.executable,
            'scripts/run_safety_eval.py',
            '--markdown-out',
            str(output),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert 'CML safety-eval benchmark' in result.stdout
    assert output.exists()
    assert '# CML Safety-Eval Results' in output.read_text(encoding='utf-8')
