"""Closed local HTTP adapter. Client session binding is not server/process isolation."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ..contracts.jsonwire import strict_json, MAX_BODY_BYTES

from ..contracts.api import TargetRequest, TargetResponse
from ..contracts.common import Uuid
from ..ports import DependencyUnavailable, TargetNotDispatched, validate_target_binding

# Legacy generic-adapter candidate only, never admission proof. The checked N04
# model/license/backend pins are in its separately frozen admission file.
MODEL_CANDIDATE_CONFIG: Dict[str, Any] = {
    "status": "UNVERIFIED_CANDIDATE",
    "candidate": "Qwen2.5-0.5B-Instruct",
    "format": "GGUF",
    "quantization": "Q4_K_M",
    "upstream_url": "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF",
    "commit_sha": None,
    "artifact_filename": "qwen2.5-0.5b-instruct-q4_k_m.gguf",
    "artifact_sha256": None,
    "tokenizer_sha256": None,
    "license": None,
    "context_window_limit": 2048,
    "max_output_tokens_cap": 256,
}

MAX_CONCURRENT_LANES = 3


class LlamaModelAdapter:
    """Closed-schema local target adapter with explicitly separate test simulation.

    Real mode requires a numeric loopback llama-server endpoint. Synthetic mode
    exercises component plumbing only and must not be reported as model evidence.
    """

    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        timeout_sec: float = 30.0,
        simulate_base_latency_us: int = 25_000,
        *,
        synthetic_mode: bool = False,
        max_lanes: int = 3,
        input_token_cap: int = 1536,
        api_key: str | None = None,
    ) -> None:
        if endpoint_url is None and not synthetic_mode:
            raise DependencyUnavailable("MODEL_UNAVAILABLE")
        if endpoint_url is not None and synthetic_mode:
            raise ValueError("synthetic_mode cannot be combined with a model endpoint")
        if endpoint_url is not None:
            parsed = urlsplit(endpoint_url)
            try:
                is_loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
            except ValueError:
                is_loopback = False
            if (
                parsed.scheme != "http"
                or not is_loopback
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise DependencyUnavailable("LOCAL_LOOPBACK_MODEL_ENDPOINT_REQUIRED")
        if type(max_lanes) is not int or not 1 <= max_lanes <= 3:
            raise ValueError("max_lanes must be 1..3")
        if type(input_token_cap) is not int or not 1 <= input_token_cap <= 1536:
            raise ValueError("input_token_cap must be 1..1536")
        if not 0 < timeout_sec <= 120:
            raise ValueError("timeout_sec must be bounded")
        self.endpoint_url = endpoint_url.rstrip("/") if endpoint_url else None
        self.timeout_sec = timeout_sec
        self.simulate_base_latency_us = simulate_base_latency_us
        self.synthetic_mode = synthetic_mode
        self.max_lanes = max_lanes
        self.input_token_cap = input_token_cap
        self.api_key = api_key

        # Client slot allocation only; N04 uses one private model process/slot.
        self.lane_ids = [f"lane-{i}" for i in range(self.max_lanes)]
        self._session_to_lane: Dict[str, str] = {}
        self._lane_contexts: Dict[str, List[Dict[str, str]]] = {
            lane: [] for lane in self.lane_ids
        }
        self._lane_locks = {lane: asyncio.Lock() for lane in self.lane_ids}
        self._poisoned_lanes: set[str] = set()
        self._bindings: dict[str, tuple] = {}
        self._next_index: dict[str, int] = {}
        self._closing_sessions: set[str] = set()

    def _check_session(self, request: TargetRequest) -> None:
        binding = (request.domain_id, request.experiment_id, request.epoch)
        old = self._bindings.get(request.session_id)
        if request.session_id in self._closing_sessions or (
            old is not None and old != binding
        ):
            raise DependencyUnavailable("MODEL_SESSION_CONTEXT_MISMATCH")
        if request.turn_index < self._next_index.get(request.session_id, 0):
            raise DependencyUnavailable("MODEL_TURN_ORDER_MISMATCH")
        self._bindings[request.session_id] = binding

    def _assign_lane(self, session_id: Uuid) -> str:
        s_id = str(session_id).lower()
        if s_id in self._session_to_lane:
            return self._session_to_lane[s_id]

        # Find least occupied lane by active sessions, then context length
        def _lane_load(lane: str) -> tuple[int, int]:
            active_sessions = sum(
                1 for mapped in self._session_to_lane.values() if mapped == lane
            )
            turns = len(self._lane_contexts[lane])
            return (active_sessions, turns)

        assigned = min(self.lane_ids, key=_lane_load)
        if _lane_load(assigned)[0] >= 1:
            raise DependencyUnavailable("MODEL_LANE_CAPACITY_EXCEEDED")
        self._session_to_lane[s_id] = assigned
        return assigned

    async def infer(self, request: TargetRequest) -> TargetResponse:
        """Infer target response enforcing closed parameters and timeout bounds."""
        # 1. Closed input validation
        text_bytes = request.text.encode("utf-8")
        if len(text_bytes) > 65_536:
            raise DependencyUnavailable("INPUT_TEXT_EXCEEDS_65536_BYTES")
        if request.max_output_tokens > 256 or request.max_output_tokens < 1:
            raise DependencyUnavailable("MAX_OUTPUT_TOKENS_INVALID")

        self._check_session(request)
        lane_id = self._assign_lane(request.session_id)
        if lane_id in self._poisoned_lanes:
            raise DependencyUnavailable("MODEL_LANE_QUARANTINED")
        async with self._lane_locks[lane_id]:
            self._check_session(request)
            if lane_id in self._poisoned_lanes:
                raise DependencyUnavailable("MODEL_LANE_QUARANTINED")
            start_ns = time.monotonic_ns()
            if self.synthetic_mode:
                response_text, input_tokens, output_tokens = self._local_cpu_inference(
                    request, lane_id
                )
                duration_us = max(
                    self.simulate_base_latency_us,
                    (time.monotonic_ns() - start_ns) // 1000,
                )
            else:
                try:
                    response_text, input_tokens, output_tokens = await asyncio.wait_for(
                        self._call_server(request, lane_id), timeout=self.timeout_sec
                    )
                except asyncio.TimeoutError as exc:
                    self._poisoned_lanes.add(lane_id)
                    raise DependencyUnavailable("DEADLINE_EXCEEDED") from exc
                except TargetNotDispatched:
                    raise
                except BaseException:
                    # Once the request may have reached the target, *any* lost or
                    # invalid ACK (including cancellation) leaves execution ambiguous.
                    self._poisoned_lanes.add(lane_id)
                    raise
                duration_us = max(1, (time.monotonic_ns() - start_ns) // 1000)
            self._next_index[request.session_id] = request.turn_index + 1

        response = TargetResponse(
            domain_id=request.domain_id,
            experiment_id=request.experiment_id,
            epoch=request.epoch,
            attempt_id=request.attempt_id,
            session_id=request.session_id,
            turn_index=request.turn_index,
            text=response_text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duration_us=duration_us,
        )

        # Enforce target context binding
        validate_target_binding(request, response)
        return response

    def _local_cpu_inference(
        self, request: TargetRequest, lane_id: str
    ) -> tuple[str, int, int]:
        """Local deterministic CPU fallback with multi-turn memory in assigned lane."""
        s_id = str(request.session_id).lower()
        # Session-isolated context within the assigned lane
        context_history = [
            h for h in self._lane_contexts[lane_id] if h.get("session_id") == s_id
        ]

        # Build prompt from session context within the lane
        full_context = "\n".join(
            [f"Turn {h['turn']}: {h['text']}" for h in context_history]
        )
        full_context += f"\nTurn {request.turn_index}: {request.text}"

        input_tokens = max(1, len(full_context.split()))

        # Hash context to produce reproducible response
        ctx_hash = hashlib.sha256(full_context.encode("utf-8")).hexdigest()

        # Generate word tokens strictly bounded by max_output_tokens
        num_tokens = min(
            request.max_output_tokens,
            max(1, (int(ctx_hash[:2], 16) % request.max_output_tokens) + 1),
        )
        words = [
            f"qwen_{ctx_hash[i : i + 4]}"
            for i in range(0, min(len(ctx_hash), num_tokens * 4), 4)
        ]
        if not words:
            words = ["qwen_resp"]
        output_tokens = len(words)
        response_text = " ".join(words)

        # Record into lane context (multi-turn continuity within session and lane)
        self._lane_contexts[lane_id].append(
            {
                "session_id": s_id,
                "turn": str(request.turn_index),
                "text": request.text,
                "resp": response_text,
            }
        )
        return response_text, input_tokens, output_tokens

    async def _call_server(
        self, request: TargetRequest, lane_id: str
    ) -> tuple[str, int, int]:
        """Call live local llama-server via loopback."""
        history = self._lane_contexts[lane_id]

        # Explicit ChatML history is sent each time; server cache reuse is disabled.
        # The selected Qwen artifact uses ChatML. This is not a generic template
        # for arbitrary models and must change together with their admission lock.
        def frame(role, text):
            return f"<|im_start|>{role}\n{text}<|im_end|>\n"

        prompt = frame("system", "You are a helpful assistant.")
        for item in history:
            prompt += frame("user", item["text"]) + frame("assistant", item["resp"])
        prompt += frame("user", request.text) + "<|im_start|>assistant\n"
        try:
            token_data = await self._request_json(
                "/tokenize", {"content": prompt, "add_special": True}
            )
        except Exception as exc:
            raise TargetNotDispatched(
                "MODEL_TOKENIZATION_FAILED_BEFORE_GENERATION"
            ) from exc
        tokens = token_data.get("tokens")
        if type(tokens) is not list or any(type(token) is not int for token in tokens):
            raise TargetNotDispatched("MODEL_TOKENIZATION_INVALID")
        if len(tokens) > self.input_token_cap:
            raise TargetNotDispatched("MODEL_INPUT_TOKEN_CAP_EXCEEDED")
        data = await self._request_json(
            "/completion",
            {
                "prompt": prompt,
                "n_predict": request.max_output_tokens,
                "id_slot": int(lane_id.split("-")[1]),
                "cache_prompt": False,
                "temperature": 0,
                "seed": 0,
                "stream": False,
            },
        )
        text, inp_tok, out_tok = (
            data.get("content"),
            data.get("tokens_evaluated"),
            data.get("tokens_predicted"),
        )
        if (
            not isinstance(text, str)
            or len(text.encode("utf-8")) > 65_536
            or type(inp_tok) is not int
            or type(out_tok) is not int
            or inp_tok < 0
            or out_tok < 0
            or out_tok > request.max_output_tokens
            or data.get("truncated", False) is not False
        ):
            raise DependencyUnavailable("MODEL_RESPONSE_INVALID")
        self._lane_contexts[lane_id].append(
            {
                "session_id": request.session_id,
                "turn": str(request.turn_index),
                "text": request.text,
                "resp": text,
            }
        )
        return text, inp_tok, out_tok

    async def _request_json(self, path, content):
        payload = json.dumps(content).encode("utf-8")

        req = Request(
            f"{self.endpoint_url}{path}",
            data=payload,
            headers={
                "Content-Type": "application/json",
                **({"Authorization": "Bearer " + self.api_key} if self.api_key else {}),
            },
        )

        loop = asyncio.get_running_loop()

        def _req():
            class RejectRedirects(HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise DependencyUnavailable("MODEL_ENDPOINT_REDIRECT_REJECTED")

            opener = build_opener(ProxyHandler({}), RejectRedirects())
            with opener.open(req, timeout=self.timeout_sec) as resp:
                return strict_json(resp.read(MAX_BODY_BYTES + 1))

        return await asyncio.wait_for(
            loop.run_in_executor(None, _req), timeout=self.timeout_sec
        )

    async def reset(self, session_id: Uuid) -> None:
        """Erase a real server slot before releasing its session assignment."""
        s_id = str(session_id).lower()
        if s_id in self._session_to_lane:
            self._closing_sessions.add(s_id)
            lane_id = self._session_to_lane[s_id]
            if lane_id in self._poisoned_lanes:
                raise DependencyUnavailable("MODEL_LANE_QUARANTINED")
            async with self._lane_locks[lane_id]:
                if not self.synthetic_mode:
                    await self._erase_server_slot(lane_id)
                self._lane_contexts[lane_id] = [
                    h
                    for h in self._lane_contexts[lane_id]
                    if h.get("session_id") != s_id
                ]
                del self._session_to_lane[s_id]
                self._bindings.pop(s_id, None)
                self._next_index.pop(s_id, None)
                self._closing_sessions.discard(s_id)

    async def _erase_server_slot(self, lane_id: str) -> None:
        """Erase the llama.cpp prompt cache; never free a slot on uncertain ACK."""
        slot_id = int(lane_id.split("-")[1])
        req = Request(
            f"{self.endpoint_url}/slots/{slot_id}?action=erase",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                **({"Authorization": "Bearer " + self.api_key} if self.api_key else {}),
            },
            method="POST",
        )
        loop = asyncio.get_running_loop()

        def _erase():
            class RejectRedirects(HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    raise DependencyUnavailable("MODEL_ENDPOINT_REDIRECT_REJECTED")

            with build_opener(ProxyHandler({}), RejectRedirects()).open(
                req, timeout=self.timeout_sec
            ) as resp:
                data = strict_json(resp.read(MAX_BODY_BYTES + 1))
                if (
                    data.get("id_slot") != slot_id
                    or type(data.get("n_erased")) is not int
                    or data["n_erased"] < 0
                ):
                    raise DependencyUnavailable("MODEL_RESET_UNCONFIRMED")

        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, _erase), timeout=self.timeout_sec
            )
        except Exception as exc:
            self._poisoned_lanes.add(lane_id)
            raise DependencyUnavailable("MODEL_RESET_UNCONFIRMED") from exc

    def get_assigned_lane(self, session_id: Uuid) -> Optional[str]:
        return self._session_to_lane.get(str(session_id).lower())

    def get_lane_turn_count(self, lane_id: str) -> int:
        return len(self._lane_contexts.get(lane_id, []))
