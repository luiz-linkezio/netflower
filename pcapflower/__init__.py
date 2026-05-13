import warnings
warnings.warn(
    "pcapflower has been renamed to netflower. "
    "Please update your imports. pcapflower will be removed in a future version.",
    DeprecationWarning,
    stacklevel=2,
)
from netflower import *  # noqa: F401, F403
from netflower import __version__  # noqa: F401
