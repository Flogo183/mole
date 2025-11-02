from __future__ import annotations
from mole.controllers.ai import AiController
from mole.controllers.config import ConfigController
from mole.controllers.path import PathController
from mole.models.config import ConfigModel
from mole.services.config import ConfigService
from mole.views.ai import AiView
from mole.views.config import ConfigView
from mole.views.path import PathView
from mole.views.sidebar import MoleSidebar
import batch_runner
import batch_runner_juliet

# Services
config_service = ConfigService()

# Models
config_model = ConfigModel(config_service.load_config())

# Views
config_view = ConfigView()
ai_view = AiView()
path_view = PathView()

# Controllers
config_ctr = ConfigController(config_service, config_model, config_view)
ai_ctr = AiController(ai_view, config_ctr)
path_ctr = PathController(path_view, config_ctr, ai_ctr)

# Initialize sidebar in Binary Ninja
sidebar = MoleSidebar(path_view)
sidebar.init()

# Expose controllers globally
__all__ = ["config_ctr", "ai_ctr", "path_ctr"]
globals()["config_ctr"] = config_ctr
globals()["ai_ctr"] = ai_ctr
globals()["path_ctr"] = path_ctr

# Initialize batch_runner with path_ctr
batch_runner.init(path_ctr)

# Initialize Juliet batch_runner with path_ctr
batch_runner_juliet.init(path_ctr)
