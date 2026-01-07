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

    # 并发配置
    max_configure_workers: int = Field(
        default=5,
        ge=1,
        le=20,
        description="并发配置节点数量"
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
        """验证 API Key 是否设置。"""
        if v is None or not v.strip():
            raise ValueError(
                "LLM_API_KEY is required. Please set it in your .env file or environment variables.\n"
                "Example: LLM_API_KEY=sk-..."
            )
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
        # 移除尾部斜杠
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

    class Config:
        """Pydantic 配置。"""
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"  # 忽略额外的环境变量
        # 环境变量映射（大写带下划线）
        populate_by_name = True


# 创建全局配置实例
def _load_config() -> AppConfig:
    """加载并验证配置。"""
    try:
        return AppConfig(
            llm_model=os.getenv("LLM_MODEL", "DeepSeek-V3.2"),
            base_url=os.getenv("LLM_BASE_URL"),
            api_key=os.getenv("LLM_API_KEY"),
            max_retries=int(os.getenv("MAX_RETRIES", "3")),
            timeout_seconds=int(os.getenv("TIMEOUT_SECONDS", "600")),
            max_configure_workers=int(os.getenv("MAX_CONFIGURE_WORKERS", "5")),
            container_health_check_interval=int(os.getenv("CONTAINER_HEALTH_CHECK_INTERVAL", "3")),
            container_health_check_max_retries=int(os.getenv("CONTAINER_HEALTH_CHECK_MAX_RETRIES", "10")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_to_file=os.getenv("LOG_TO_FILE", "true").lower() == "true"
        )
    except Exception as e:
        print(f"❌ Configuration Error: {e}")
        print("\nPlease check your .env file or environment variables.")
        print("\nRequired environment variables:")
        print("  - LLM_API_KEY: Your LLM API key")
        print("\nOptional environment variables:")
        print("  - LLM_MODEL: Model name (default: DeepSeek-V3.2)")
        print("  - LLM_BASE_URL: API base URL")
        print("  - MAX_RETRIES: Maximum retry attempts (default: 3)")
        print("  - TIMEOUT_SECONDS: Operation timeout (default: 600)")
        print("  - LOG_LEVEL: Logging level (default: INFO)")
        raise


# 加载配置
try:
    config = _load_config()
except Exception:
    # 在导入时就失败，让用户知道配置有问题
    import sys
    sys.exit(1)

# 向后兼容的导出
LLM_MODEL = config.llm_model
BASE_URL = config.base_url
API_KEY = config.api_key
MAX_RETRIES = config.max_retries
TIMEOUT_SECONDS = config.timeout_seconds
MAX_CONFIGURE_WORKERS = config.max_configure_workers