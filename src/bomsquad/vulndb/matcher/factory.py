from univers.versions import PypiVersion
from univers.versions import Version


class VersionFactory:
    @classmethod
    def for_ecosystem_version(cls, ecosystem: str, spec: str) -> Version:
        if ecosystem == "pypi":
            return PypiVersion(spec)
        raise ValueError("Unknown ecosystem")
