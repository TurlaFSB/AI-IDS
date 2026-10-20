import logging
from collections.abc import Iterator
from pathlib import Path

import pandas as pd
import pytest

from ai_ids.data.loader import clean_flows, read_csv_file
from ai_ids.data.synthetic import generate_flows


@pytest.fixture(scope="session")
def synthetic_csv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("data") / "flows.csv"
    generate_flows(8_000, seed=7).to_csv(path, index=False, encoding="latin-1")
    return path


@pytest.fixture(scope="session")
def cleaned(synthetic_csv: Path) -> pd.DataFrame:
    df, _ = clean_flows(read_csv_file(synthetic_csv))
    return df


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """`configure_logging` binds a handler to the current stderr; undo that after every test.

    Otherwise a handler bound to pytest's captured (later closed) stream can outlive its test and
    background threads, such as a live server, then fail with "Logging error" noise.
    """
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
