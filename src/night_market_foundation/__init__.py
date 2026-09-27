"""技能赛训协作基础服务的服务端基础包。"""

from .incidents import IncidentService
from .service import DomainService

__all__ = ["DomainService", "IncidentService"]
