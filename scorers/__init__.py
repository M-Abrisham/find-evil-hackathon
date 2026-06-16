"""Scorer registry — all scorers exported here for Braintrust Eval."""

from scorers.a1_no_fabricated_paths import score as no_fabricated_paths
from scorers.a2_correct_tool import score as correct_tool
from scorers.a3_skill_triggered import score as skill_triggered
from scorers.a4_audit_log_integrity import score as audit_log_integrity
from scorers.a5_utc_timestamps import score as utc_timestamps
from scorers.a6_evidence_readonly import score as evidence_readonly
from scorers.a7_no_connectors import score as no_connectors
from scorers.a8_no_answer_key import score as no_answer_key
from scorers.s1_tool_path_v3 import score as tool_path_v3
from scorers.s2_memory_workflow_order import score as memory_workflow_order
from scorers.s3_velociraptor_not_cli import score as velociraptor_not_cli
from scorers.s4_export_naming import score as export_naming
from scorers.s5_yara_condition_order import score as yara_condition_order
from scorers.s6_skill_routing_negative import score as skill_routing_negative
from scorers.s7_required_flags import score as required_flags
from scorers.s8_clean_image_fp_test import score as clean_image_fp_test

ALL = [
    no_fabricated_paths,
    correct_tool,
    skill_triggered,
    audit_log_integrity,
    utc_timestamps,
    evidence_readonly,
    no_connectors,
    no_answer_key,
    tool_path_v3,
    memory_workflow_order,
    velociraptor_not_cli,
    export_naming,
    yara_condition_order,
    skill_routing_negative,
    required_flags,
    clean_image_fp_test,
]
