import os
import time
from typing import Tuple, Dict, Any, Optional
from runner import config


class LLMClient:
    def __init__(self, provider: Optional[str] = None, model: Optional[str] = None):
        self.provider = (provider or config.LLM_PROVIDER).lower()
        if self.provider == "gemini":
            self.model = model or config.GEMINI_MODEL
            self.api_key = config.GEMINI_API_KEY
        else:
            self.provider = "openai"
            self.model = model or config.OPENAI_MODEL
            self.api_key = config.OPENAI_API_KEY

    def generate(self, prompt: str, system_prompt: str = "") -> Tuple[str, int, int, float]:
        """
        Calls the configured LLM API.
        Returns: (response_text, input_tokens, output_tokens, latency_seconds)
        """
        start_time = time.time()

        if not self.api_key or self.api_key.startswith("your-"):
            raise ValueError(
                f"API Key for {self.provider.upper()} is not configured. "
                f"Please set {self.provider.upper()}_API_KEY in your .env file."
            )

        if self.provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model_instance = genai.GenerativeModel(
                model_name=self.model,
                system_instruction=system_prompt if system_prompt else None,
                generation_config={"temperature": config.LLM_TEMPERATURE}
            )
            response = model_instance.generate_content(prompt)
            latency = time.time() - start_time
            
            # Extract token counts
            usage = getattr(response, "usage_metadata", None)
            input_tokens = getattr(usage, "prompt_token_count", len(prompt) // 4)
            output_tokens = getattr(usage, "candidates_token_count", len(response.text) // 4)
            return response.text, input_tokens, output_tokens, round(latency, 3)

        else:  # OpenAI
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key)
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            kwargs = {
                "model": self.model,
                "messages": messages,
            }
            # Certain reasoning or new models only allow default temperature or reject 0.0
            if "sol" not in self.model.lower() and "o1" not in self.model.lower() and "o3" not in self.model.lower():
                kwargs["temperature"] = config.LLM_TEMPERATURE

            try:
                response = client.chat.completions.create(**kwargs)
            except Exception as exc:
                # If temperature failed, retry without explicit temperature
                if "temperature" in str(exc).lower():
                    kwargs.pop("temperature", None)
                    response = client.chat.completions.create(**kwargs)
                else:
                    raise exc

            latency = time.time() - start_time
            response_text = response.choices[0].message.content or ""
            input_tokens = response.usage.prompt_tokens if response.usage else len(prompt) // 4
            output_tokens = response.usage.completion_tokens if response.usage else len(response_text) // 4
            return response_text, input_tokens, output_tokens, round(latency, 3)

