from pathlib import Path
import pytest

HAS_PROCFS = Path("/proc/self/stat").exists()

needs_procfs = pytest.mark.skipif(
    not HAS_PROCFS, reason="requires a live /proc filesystem"
)
