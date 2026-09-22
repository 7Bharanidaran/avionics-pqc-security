"""Phase 13: Research-Grade Evaluation & Ablation Framework.

Provides rigorous scientific benchmarking, baseline comparisons, ablation studies,
and safety validation for the AI-assisted adaptive cryptographic avionics architecture.
"""

from .scenarios import (
    EVAL_SCENARIOS,
    EvalScenario,
    EvalStepInput,
    get_scenario,
    list_scenarios,
)
from .baselines import (
    BASELINE_STATIC,
    BASELINE_RULE,
    AI_ADAPTIVE,
    EvaluationHarness,
    SystemConfiguration,
)
from .metrics import (
    SecurityMetrics,
    AdaptationMetrics,
    PerformanceMetrics,
    AIMetrics,
    ComprehensiveMetrics,
    compute_scenario_metrics,
    compute_comparative_metrics,
)
from .ablation import (
    AblationStudy,
    AblationConfiguration,
    AblationResult,
    run_ablation_study,
    run_safety_ablation,
)
from .runner import (
    EvaluationRunner,
    run_full_evaluation,
)

__all__ = [
    "EVAL_SCENARIOS",
    "EvalScenario",
    "EvalStepInput",
    "get_scenario",
    "list_scenarios",
    "BASELINE_STATIC",
    "BASELINE_RULE",
    "AI_ADAPTIVE",
    "EvaluationHarness",
    "SystemConfiguration",
    "SecurityMetrics",
    "AdaptationMetrics",
    "PerformanceMetrics",
    "AIMetrics",
    "ComprehensiveMetrics",
    "compute_scenario_metrics",
    "compute_comparative_metrics",
    "AblationStudy",
    "AblationConfiguration",
    "AblationResult",
    "run_ablation_study",
    "run_safety_ablation",
    "EvaluationRunner",
    "run_full_evaluation",
]
