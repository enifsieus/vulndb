import logging
import os
from importlib import resources
from pathlib import Path
from typing import cast
from typing import Optional

import tomli
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class Config(BaseModel):
    database: str
    username: str
    password: str
    nvd_api_key: Optional[str] = None
    request_delay: int
    gcloud_project: str

    @classmethod
    def resolve_config(cls) -> Path:
        """
        Resolve the active configuration from one of the packaged defaults, or a local configuraion
        loaded from $HOME/.watts/config.toml.
        """
        home_config = Path(f"{os.getenv('HOME')}/.vulndb/config.toml")
        if home_config.exists():
            logger.info(f"Using config from {home_config}")
            return home_config
        logger.info("Using built-in default config")
        return cast(Path, resources.files("bomsquad.vulndb").joinpath("config.toml"))

    @classmethod
    def load(cls) -> "Config":
        with cls.resolve_config().open("rb") as fh:
            obj = tomli.load(fh)["vulndb"]
            config = Config.parse_obj(obj)
            return config


config = Config.load()
