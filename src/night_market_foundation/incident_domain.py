"""定义跨专区事件指挥模块使用的枚举与常量。"""

from __future__ import annotations

# 值班指挥是基础角色之外新增的领域角色
INCIDENT_ROLE_COMMANDER = "commander"

# 可以查看健康信息、联系方式等敏感内容的角色；报告人本人始终可见自己的报告
SENSITIVE_ROLES = frozenset({"admin", "commander", "reviewer"})

# 可以登记一线报告的角色
REPORT_ROLES = frozenset({"admin", "commander", "operator"})

# 事件等级，数值越大级别越高，升级只能向更高等级移动
LEVELS = ("standard", "elevated", "critical")
LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}

# 事件状态：开放、已结案、复开
INCIDENT_OPEN = "open"
INCIDENT_CLOSED = "closed"
INCIDENT_REOPENED = "reopened"
INCIDENT_STATUSES = frozenset({INCIDENT_OPEN, INCIDENT_CLOSED, INCIDENT_REOPENED})

# 合并候选状态
CANDIDATE_PROPOSED = "proposed"
CANDIDATE_CONFIRMED = "confirmed"
CANDIDATE_REJECTED = "rejected"

# 行动状态
ACTION_OPEN = "open"
ACTION_IN_PROGRESS = "in_progress"
ACTION_COMPLETED = "completed"
ACTION_CANCELLED = "cancelled"
ACTION_STATUSES = frozenset({ACTION_OPEN, ACTION_IN_PROGRESS, ACTION_COMPLETED, ACTION_CANCELLED})
# 允许的状态迁移
ACTION_TRANSITIONS = {
    ACTION_OPEN: frozenset({ACTION_IN_PROGRESS, ACTION_CANCELLED}),
    ACTION_IN_PROGRESS: frozenset({ACTION_COMPLETED, ACTION_CANCELLED}),
    ACTION_COMPLETED: frozenset(),
    ACTION_CANCELLED: frozenset(),
}
# 结案前必须清空的未决状态
ACTION_PENDING_STATUSES = frozenset({ACTION_OPEN, ACTION_IN_PROGRESS})

# 调援状态
SUPPORT_REQUESTED = "requested"
SUPPORT_FULFILLED = "fulfilled"
SUPPORT_CANCELLED = "cancelled"

# 交接状态
HANDOVER_PROPOSED = "proposed"
HANDOVER_COMPLETED = "completed"
HANDOVER_CANCELLED = "cancelled"

# 结案状态
CLOSURE_PROPOSED = "proposed"
CLOSURE_CONFIRMED = "confirmed"
CLOSURE_REJECTED = "rejected"

# 迟到报告处置方式
LATE_SUPPLEMENT = "supplement_evidence"
LATE_REOPEN = "reopen_application"
LATE_MODES = frozenset({LATE_SUPPLEMENT, LATE_REOPEN})

# 复开申请状态
REOPEN_PENDING = "pending"
REOPEN_APPROVED = "approved"
REOPEN_REJECTED = "rejected"

# 关联规则名称
RULE_SAME_EVIDENCE = "identical_evidence"
RULE_NEAR_DUPLICATE = "near_duplicate"
RULE_SAME_LOCATION = "same_location_time"

# 近重复判定窗口（分钟）
NEAR_DUPLICATE_WINDOW_MINUTES = 30
# 同地点候选的判定窗口（分钟）
SAME_LOCATION_WINDOW_MINUTES = 30
# 一次交接的最长期限（小时），指挥权必须是有期限转移
MAX_HANDOVER_HOURS = 24
