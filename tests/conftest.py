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
