//! Continuous Stochastic Authentication
//!
//! Unpredictable authentication using Poisson process to prevent timing attacks.

use rand::Rng;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// Continuous stochastic authentication using Poisson process
///
/// Authentication events occur randomly but with predictable aggregate rate,
/// preventing MITM from predicting safe windows.
///
/// Mathematical foundation: Memoryless Poisson process
pub struct ContinuousStochasticAuth {
    lambda_param: f64,
    threshold: f64,
    is_running: Arc<Mutex<bool>>,
    auth_checks: Arc<Mutex<u64>>,
    auth_successes: Arc<Mutex<u64>>,
    auth_failures: Arc<Mutex<u64>>,
    last_auth_time: Arc<Mutex<f64>>,
}

impl ContinuousStochasticAuth {
    /// Create new continuous stochastic auth
    ///
    /// # Arguments
    /// * `lambda_param` - Poisson process rate (events per second)
    /// * `threshold` - Probability threshold for authentication
    pub fn new(lambda_param: f64, threshold: f64) -> Self {
        Self {
            lambda_param,
            threshold,
            is_running: Arc::new(Mutex::new(false)),
            auth_checks: Arc::new(Mutex::new(0)),
            auth_successes: Arc::new(Mutex::new(0)),
            auth_failures: Arc::new(Mutex::new(0)),
            last_auth_time: Arc::new(Mutex::new(current_time())),
        }
    }

    /// Determine if authentication should occur now (Poisson process)
    ///
    /// Returns true if authentication should occur
    fn should_authenticate_now(&self) -> bool {
        let mut rng = rand::thread_rng();
        // Exponential distribution (memoryless property)
        let sample = -self.lambda_param.recip() * rng.gen::<f64>().ln();
        sample < self.threshold
    }

    /// Perform fast authentication check
    ///
    /// Returns true if authentication successful
    pub async fn perform_lightning_auth(&self) -> bool {
        let mut checks = self.auth_checks.lock().await;
        *checks += 1;
        drop(checks);

        let mut last_auth = self.last_auth_time.lock().await;
        *last_auth = current_time();
        drop(last_auth);

        // Simulate fast auth (1ms auth check)
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;

        // In production, this would verify session key, certificates, etc.
        // For now, simulate successful authentication
        let is_valid = true;

        if is_valid {
            let mut successes = self.auth_successes.lock().await;
            *successes += 1;
        } else {
            let mut failures = self.auth_failures.lock().await;
            *failures += 1;
        }

        is_valid
    }

    /// Continuous verification loop
    async fn continuous_verification<F>(&self, auth_callback: Option<F>)
    where
        F: Fn(bool) + Send + 'static,
    {
        loop {
            {
                let is_running = self.is_running.lock().await;
                if !*is_running {
                    break;
                }
            }

            if self.should_authenticate_now() {
                let is_valid = self.perform_lightning_auth().await;

                if let Some(ref callback) = auth_callback {
                    callback(is_valid);
                }

                if !is_valid {
                    eprintln!("[STOCHASTIC_AUTH] ⚠️ Authentication failed!");
                }
            }

            // Check every millisecond
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        }
    }

    /// Start continuous monitoring
    pub async fn start_monitoring<F>(&self, auth_callback: Option<F>)
    where
        F: Fn(bool) + Send + 'static,
    {
        {
            let mut is_running = self.is_running.lock().await;
            if *is_running {
                return;
            }
            *is_running = true;
        }

        let auth = self.clone();
        tokio::spawn(async move {
            auth.continuous_verification(auth_callback).await;
        });
    }

    /// Stop continuous monitoring
    pub async fn stop_monitoring(&self) {
        let mut is_running = self.is_running.lock().await;
        *is_running = false;
    }

    /// Calculate expected cost of continuous verification
    ///
    /// Returns expected cost (λ × cost_per_verification)
    pub fn get_expected_cost(&self) -> f64 {
        let cost_per_verification = 0.001; // 1ms
        self.lambda_param * cost_per_verification
    }

    /// Get stochastic auth statistics
    pub async fn get_stats(&self) -> StochasticAuthStats {
        let checks = *self.auth_checks.lock().await;
        let successes = *self.auth_successes.lock().await;
        let failures = *self.auth_failures.lock().await;
        let last_auth = *self.last_auth_time.lock().await;
        let is_running = *self.is_running.lock().await;

        StochasticAuthStats {
            auth_checks: checks,
            auth_successes: successes,
            auth_failures: failures,
            success_rate: if checks > 0 {
                successes as f64 / checks as f64
            } else {
                0.0
            },
            failure_rate: if checks > 0 {
                failures as f64 / checks as f64
            } else {
                0.0
            },
            last_auth,
            expected_cost_ms: self.get_expected_cost() * 1000.0,
            is_running,
        }
    }
}

impl Clone for ContinuousStochasticAuth {
    fn clone(&self) -> Self {
        Self {
            lambda_param: self.lambda_param,
            threshold: self.threshold,
            is_running: Arc::clone(&self.is_running),
            auth_checks: Arc::clone(&self.auth_checks),
            auth_successes: Arc::clone(&self.auth_successes),
            auth_failures: Arc::clone(&self.auth_failures),
            last_auth_time: Arc::clone(&self.last_auth_time),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StochasticAuthStats {
    pub auth_checks: u64,
    pub auth_successes: u64,
    pub auth_failures: u64,
    pub success_rate: f64,
    pub failure_rate: f64,
    pub last_auth: f64,
    pub expected_cost_ms: f64,
    pub is_running: bool,
}

fn current_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stochastic_auth_basic() {
        let auth = ContinuousStochasticAuth::new(0.1, 0.5);
        let result = auth.perform_lightning_auth().await;
        assert!(result);

        let stats = auth.get_stats().await;
        assert_eq!(stats.auth_checks, 1);
        assert_eq!(stats.auth_successes, 1);
    }

    #[tokio::test]
    async fn test_monitoring() {
        let auth = ContinuousStochasticAuth::new(0.1, 0.5);
        
        auth.start_monitoring::<fn(bool)>(None).await;
        
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        auth.stop_monitoring().await;

        let stats = auth.get_stats().await;
        assert!(!stats.is_running);
    }

    #[test]
    fn test_expected_cost() {
        let auth = ContinuousStochasticAuth::new(0.1, 0.5);
        let cost = auth.get_expected_cost();
        assert!(cost > 0.0);
        assert!(cost < 1.0); // Should be less than 1 second
    }

    #[tokio::test]
    async fn test_poisson_distribution() {
        let auth = ContinuousStochasticAuth::new(0.1, 0.5);
        
        let mut auth_count = 0;
        for _ in 0..1000 {
            if auth.should_authenticate_now() {
                auth_count += 1;
            }
        }

        // With lambda=0.1 and threshold=0.5, we expect some authentications
        // but not all (stochastic nature)
        assert!(auth_count > 0);
        assert!(auth_count < 1000);
    }
}
