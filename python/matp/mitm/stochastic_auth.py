"""
Continuous Stochastic Authentication

Unpredictable authentication using Poisson process to prevent timing attacks.
"""

import asyncio
import random
import time
from typing import Optional, Callable


class ContinuousStochasticAuth:
    """
    Continuous stochastic authentication using Poisson process.
    
    Authentication events occur randomly but with predictable aggregate rate,
    preventing MITM from predicting safe windows.
    
    Mathematical foundation: Memoryless Poisson process
    """
    
    def __init__(self, lambda_param: float = 0.1, threshold: float = 0.5):
        """
        Initialize continuous stochastic auth.
        
        Args:
            lambda_param: Poisson process rate (events per second)
            threshold: Probability threshold for authentication
        """
        self.lambda_param = lambda_param
        self.threshold = threshold
        self.is_running = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        self.auth_checks = 0
        self.auth_successes = 0
        self.auth_failures = 0
        self.last_auth_time = time.time()
    
    def should_authenticate_now(self) -> bool:
        """
        Determine if authentication should occur now (Poisson process).
        
        Returns:
            True if authentication should occur
        """
        # Exponential distribution (memoryless property)
        return random.expovariate(self.lambda_param) < self.threshold
    
    async def perform_lightning_auth(self) -> bool:
        """
        Perform fast authentication check.
        
        Returns:
            True if authentication successful
        """
        self.auth_checks += 1
        self.last_auth_time = time.time()
        
        # Simulate fast auth (in production, this would verify session key, etc.)
        await asyncio.sleep(0.001)  # 1ms auth check
        
        # For now, always succeed (in production, would do real verification)
        is_valid = True
        
        if is_valid:
            self.auth_successes += 1
        else:
            self.auth_failures += 1
        
        return is_valid
    
    async def continuous_verification(self, auth_callback: Optional[Callable] = None):
        """
        Continuous verification loop.
        
        Args:
            auth_callback: Optional callback for authentication events
        """
        while self.is_running:
            if self.should_authenticate_now():
                is_valid = await self.perform_lightning_auth()
                
                if auth_callback:
                    await auth_callback(is_valid)
                
                if not is_valid:
                    # Authentication failed - potential MITM
                    print("[STOCHASTIC_AUTH] ⚠️ Authentication failed!")
            
            # Check every millisecond
            await asyncio.sleep(0.001)
    
    async def start_monitoring(self, auth_callback: Optional[Callable] = None):
        """
        Start continuous monitoring.
        
        Args:
            auth_callback: Optional callback for authentication events
        """
        if self.is_running:
            return
        
        self.is_running = True
        self._monitor_task = asyncio.create_task(
            self.continuous_verification(auth_callback)
        )
    
    async def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
    
    def get_expected_cost(self) -> float:
        """
        Calculate expected cost of continuous verification.
        
        Returns:
            Expected cost (λ × cost_per_verification)
        """
        cost_per_verification = 0.001  # 1ms
        return self.lambda_param * cost_per_verification
    
    def get_stats(self) -> dict:
        """Get stochastic auth statistics"""
        return {
            "auth_checks": self.auth_checks,
            "auth_successes": self.auth_successes,
            "auth_failures": self.auth_failures,
            "success_rate": self.auth_successes / self.auth_checks if self.auth_checks > 0 else 0,
            "failure_rate": self.auth_failures / self.auth_checks if self.auth_checks > 0 else 0,
            "last_auth": self.last_auth_time,
            "expected_cost_ms": self.get_expected_cost() * 1000,
            "is_running": self.is_running
        }
