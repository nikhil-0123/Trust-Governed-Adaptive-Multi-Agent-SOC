import abc
import hashlib
from typing import Dict, Any, Optional
from pydantic import BaseModel

class LLMProviderError(Exception):
    """Base exception for LLM provider errors."""
    pass

class LLMProviderConfigurationError(LLMProviderError):
    """Raised when provider configuration is invalid."""
    pass

class LLMProviderTimeoutError(LLMProviderError):
    """Raised when the LLM provider exceeds the configured timeout."""
    pass

class ProviderResponse(BaseModel):
    """
    Represents the RAW MODEL OUTPUT from an LLM.
    
    This is NOT a validated Claim, verified claim, authoritative evidence, 
    MITRE fact, Trust/Risk result, or governance decision.
    It must be passed through the EvidenceValidator and subsequent agents.
    """
    content: str
    provider: str
    model: str
    request_id: str
    metadata: Dict[str, Any] = {}

class LLMProvider(abc.ABC):
    """Abstract base class defining the boundary for an LLM provider."""
    
    @abc.abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        timeout_seconds: int
    ) -> ProviderResponse:
        """
        Generate raw model output from given prompts.
        Must not execute content or make unauthorized external calls.
        """
        pass
        
    def _validate_inputs(self, system_prompt: str, user_prompt: str, model: str, timeout_seconds: int):
        if not isinstance(system_prompt, str):
            raise ValueError("system_prompt must be a string")
        if not isinstance(user_prompt, str):
            raise ValueError("user_prompt must be a string")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string")
        if not isinstance(timeout_seconds, int) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive integer")

class MockLLMProvider(LLMProvider):
    """
    A deterministic mock provider that performs no network communication.
    Returns a configured string response.
    """
    def __init__(self, response: str = '{"claims":[]}'):
        self._response = response
        self.simulate_failure: Optional[Exception] = None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        model: str,
        timeout_seconds: int
    ) -> ProviderResponse:
        
        self._validate_inputs(system_prompt, user_prompt, model, timeout_seconds)
        
        if self.simulate_failure:
            raise self.simulate_failure
            
        # Create deterministic request_id using hash of inputs
        prompt_hash = hashlib.sha256(
            f"{system_prompt}{user_prompt}{model}".encode()
        ).hexdigest()[:16]
        
        return ProviderResponse(
            content=self._response,
            provider="mock",
            model=model,
            request_id=f"mock-{prompt_hash}",
            metadata={"deterministic": True}
        )

def get_llm_provider(config: Dict[str, Any]) -> LLMProvider:
    """Factory to instantiate the appropriate provider based on config."""
    provider_name = config.get("provider")
    
    if provider_name == "mock":
        # Check if we should inject a specific simulated response
        mock_response = config.get("mock_response", '{"claims":[]}')
        return MockLLMProvider(response=mock_response)
    
    raise LLMProviderConfigurationError(f"Unsupported provider requested: {provider_name}")
