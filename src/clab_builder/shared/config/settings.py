"""配置管理模块

提供配置验证、默认值管理和环境变量加载。
"""
import os
from typing import Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

load_dotenv()


class AppConfig(BaseModel):
    """应用配置模型，提供类型安全和验证。"""

    # LLM 配置
    llm_model: str = Field(
        default="DeepSeek-V3.2",
        description="LLM 模型名称"
    )
    base_url: Optional[str] = Field(
        default=None,
        description="LLM API 基础 URL"
    )
    api_key: Optional[str] = Field(
        default=None,
        description="LLM API 密钥"
    )

    # 工作流配置
    max_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="最大重试次数"
    )
    timeout_seconds: int = Field(
        default=600,
        ge=60,
        le=3600,
        description="操作超时时间（秒）"
    )

    # 容器配置
    container_health_check_interval: int = Field(
        default=3,
        ge=1,
        le=30,
        description="容器健康检查间隔（秒）"
    )
    container_health_check_max_retries: int = Field(
        default=10,
        ge=1,
        le=60,
        description="容器健康检查最大重试次数"
    )

    # 日志配置
    log_level: str = Field(
        default="INFO",
        description="日志级别 (DEBUG/INFO/WARNING/ERROR/CRITICAL)"
    )
    log_to_file: bool = Field(
        default=True,
        description="是否记录日志到文件"
    )

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: Optional[str]) -> Optional[str]:
        """验证 API Key。允许为空（非 Agent 功能不需要）。"""
        if v is None or not v.strip():
            return None
        return v.strip()

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """验证日志级别。"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(
                f"Invalid log level: {v}. Must be one of {valid_levels}"
            )
        return v_upper

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: Optional[str]) -> Optional[str]:
        """验证并清理 Base URL。"""
        if v is None:
            return None
        v = v.strip()
        if v and not v.startswith(("http://", "https://")):
            raise ValueError(f"Invalid base URL: {v}. Must start with http:// or https://")
        return v.rstrip("/")

    def get_llm_config(self) -> dict:
        """获取 LLM 配置字典。"""
        config = {
            "model": self.llm_model,
            "api_key": self.api_key,
        }
        if self.base_url:
            config["base_url"] = self.base_url
        return config

    def is_llm_configured(self) -> bool:
        """检查 LLM 是否已配置（API key 存在）。"""
        return self.api_key is not None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"
        populate_by_name = True


def load_config() -> AppConfig:
    """加载并验证配置。不会在导入时退出。"""
    return AppConfig(
        llm_model=os.getenv("LLM_MODEL", "DeepSeek-V3.2"),
        base_url=os.getenv("LLM_BASE_URL"),
        api_key=os.getenv("LLM_API_KEY"),
        max_retries=int(os.getenv("MAX_RETRIES", "3")),
        timeout_seconds=int(os.getenv("TIMEOUT_SECONDS", "600")),
        container_health_check_interval=int(os.getenv("CONTAINER_HEALTH_CHECK_INTERVAL", "3")),
        container_health_check_max_retries=int(os.getenv("CONTAINER_HEALTH_CHECK_MAX_RETRIES", "10")),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_to_file=os.getenv("LOG_TO_FILE", "true").lower() == "true"
    )


# 延迟加载的全局配置实例
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """获取全局配置实例（延迟加载）。"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


# 向后兼容：模块级属性访问
def __getattr__(name):
    """延迟加载配置属性，避免导入时崩溃。"""
    config = get_config()
    compat_map = {
        "config": config,
        "LLM_MODEL": config.llm_model,
        "BASE_URL": config.base_url,
        "API_KEY": config.api_key,
        "MAX_RETRIES": config.max_retries,
        "TIMEOUT_SECONDS": config.timeout_seconds,
    }
    if name in compat_map:
        return compat_map[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
