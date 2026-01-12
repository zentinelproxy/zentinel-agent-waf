//! Differential Privacy for Federated Learning
//!
//! Implements privacy-preserving mechanisms to protect individual training samples.

use rand::Rng;
use rand_distr::{Distribution, Normal};

/// Differential privacy mechanism
pub struct DifferentialPrivacy {
    /// Privacy budget (epsilon)
    epsilon: f64,
    /// Delta parameter for (epsilon, delta)-DP
    delta: f64,
    /// Sensitivity bound
    sensitivity: f64,
    /// Noise mechanism
    mechanism: NoiseMechanism,
}

/// Privacy budget tracker
#[derive(Debug, Clone)]
pub struct PrivacyBudget {
    /// Total epsilon budget
    pub total_epsilon: f64,
    /// Consumed epsilon
    pub consumed_epsilon: f64,
    /// Total delta budget
    pub total_delta: f64,
    /// Consumed delta
    pub consumed_delta: f64,
}

impl PrivacyBudget {
    /// Create new budget
    pub fn new(epsilon: f64, delta: f64) -> Self {
        Self {
            total_epsilon: epsilon,
            consumed_epsilon: 0.0,
            total_delta: delta,
            consumed_delta: 0.0,
        }
    }

    /// Check if budget allows a query with given cost
    pub fn can_spend(&self, epsilon: f64, delta: f64) -> bool {
        self.consumed_epsilon + epsilon <= self.total_epsilon
            && self.consumed_delta + delta <= self.total_delta
    }

    /// Spend from the budget
    pub fn spend(&mut self, epsilon: f64, delta: f64) -> bool {
        if self.can_spend(epsilon, delta) {
            self.consumed_epsilon += epsilon;
            self.consumed_delta += delta;
            true
        } else {
            false
        }
    }

    /// Get remaining epsilon
    pub fn remaining_epsilon(&self) -> f64 {
        self.total_epsilon - self.consumed_epsilon
    }

    /// Get remaining delta
    pub fn remaining_delta(&self) -> f64 {
        self.total_delta - self.consumed_delta
    }

    /// Check if budget is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.consumed_epsilon >= self.total_epsilon
            || self.consumed_delta >= self.total_delta
    }
}

/// Noise mechanism type
#[derive(Debug, Clone, Copy)]
pub enum NoiseMechanism {
    /// Gaussian noise for (epsilon, delta)-DP
    Gaussian,
    /// Laplace noise for pure epsilon-DP
    Laplace,
}

impl DifferentialPrivacy {
    /// Create new DP mechanism with Gaussian noise
    pub fn new(epsilon: f64) -> Self {
        Self {
            epsilon,
            delta: 1e-5,
            sensitivity: 1.0,
            mechanism: NoiseMechanism::Gaussian,
        }
    }

    /// Create with custom parameters
    pub fn with_params(epsilon: f64, delta: f64, sensitivity: f64) -> Self {
        Self {
            epsilon,
            delta,
            sensitivity,
            mechanism: NoiseMechanism::Gaussian,
        }
    }

    /// Use Laplace mechanism
    pub fn with_laplace(mut self) -> Self {
        self.mechanism = NoiseMechanism::Laplace;
        self
    }

    /// Add noise to gradients
    pub fn add_noise(&self, gradients: &[f32]) -> Vec<f32> {
        let mut rng = rand::thread_rng();

        match self.mechanism {
            NoiseMechanism::Gaussian => self.add_gaussian_noise(gradients, &mut rng),
            NoiseMechanism::Laplace => self.add_laplace_noise(gradients, &mut rng),
        }
    }

    /// Add Gaussian noise for (epsilon, delta)-DP
    fn add_gaussian_noise(&self, gradients: &[f32], rng: &mut impl Rng) -> Vec<f32> {
        // Compute noise scale: sigma = sensitivity * sqrt(2 * ln(1.25/delta)) / epsilon
        let sigma = self.sensitivity * (2.0 * (1.25 / self.delta).ln()).sqrt() / self.epsilon;

        let normal = Normal::new(0.0, sigma).unwrap();
        gradients.iter()
            .map(|&g| g + normal.sample(rng) as f32)
            .collect()
    }

    /// Add Laplace noise for pure epsilon-DP
    fn add_laplace_noise(&self, gradients: &[f32], rng: &mut impl Rng) -> Vec<f32> {
        // Laplace scale: b = sensitivity / epsilon
        let scale = self.sensitivity / self.epsilon;

        gradients.iter()
            .map(|&g| {
                let u: f64 = rng.gen::<f64>() - 0.5;
                let laplace = -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln();
                g + laplace as f32
            })
            .collect()
    }

    /// Clip gradients to bound sensitivity
    pub fn clip_gradients(&self, gradients: &mut [f32], max_norm: f32) {
        let norm: f32 = gradients.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > max_norm {
            let scale = max_norm / norm;
            for g in gradients.iter_mut() {
                *g *= scale;
            }
        }
    }

    /// Get the noise scale being used
    pub fn noise_scale(&self) -> f64 {
        match self.mechanism {
            NoiseMechanism::Gaussian => {
                self.sensitivity * (2.0 * (1.25 / self.delta).ln()).sqrt() / self.epsilon
            }
            NoiseMechanism::Laplace => self.sensitivity / self.epsilon,
        }
    }

    /// Compute privacy loss for a query
    pub fn privacy_loss(&self, num_queries: u32) -> (f64, f64) {
        // Simple composition (not tight, but safe)
        let epsilon_loss = self.epsilon * num_queries as f64;
        let delta_loss = self.delta * num_queries as f64;
        (epsilon_loss, delta_loss)
    }

    /// Get epsilon value
    pub fn epsilon(&self) -> f64 {
        self.epsilon
    }

    /// Get delta value
    pub fn delta(&self) -> f64 {
        self.delta
    }
}

/// Secure aggregation for multi-party computation
pub struct SecureAggregation {
    /// Number of participants
    num_participants: usize,
    /// Threshold for aggregation
    threshold: usize,
    /// Secret shares
    shares: Vec<Vec<f32>>,
}

impl SecureAggregation {
    /// Create new secure aggregation instance
    pub fn new(num_participants: usize) -> Self {
        Self {
            num_participants,
            threshold: num_participants / 2 + 1,
            shares: Vec::new(),
        }
    }

    /// Create with custom threshold
    pub fn with_threshold(num_participants: usize, threshold: usize) -> Self {
        Self {
            num_participants,
            threshold,
            shares: Vec::new(),
        }
    }

    /// Generate secret shares for a gradient vector
    pub fn create_shares(&self, gradients: &[f32]) -> Vec<Vec<f32>> {
        let mut rng = rand::thread_rng();
        let mut shares: Vec<Vec<f32>> = (0..self.num_participants)
            .map(|_| vec![0.0; gradients.len()])
            .collect();

        for (i, &g) in gradients.iter().enumerate() {
            // Generate n-1 random shares
            let mut sum = 0.0f32;
            for share in shares.iter_mut().take(self.num_participants - 1) {
                let random: f32 = rng.gen::<f32>() * 2.0 - 1.0;
                share[i] = random;
                sum += random;
            }
            // Last share makes sum equal to original value
            shares[self.num_participants - 1][i] = g - sum;
        }

        shares
    }

    /// Add a share to the aggregation
    pub fn add_share(&mut self, share: Vec<f32>) {
        self.shares.push(share);
    }

    /// Check if enough shares have been collected
    pub fn has_threshold(&self) -> bool {
        self.shares.len() >= self.threshold
    }

    /// Aggregate collected shares
    pub fn aggregate(&self) -> Option<Vec<f32>> {
        if !self.has_threshold() {
            return None;
        }

        let len = self.shares.first()?.len();
        let mut result = vec![0.0; len];

        for share in &self.shares {
            for (i, &v) in share.iter().enumerate() {
                if i < result.len() {
                    result[i] += v;
                }
            }
        }

        Some(result)
    }

    /// Reset for next round
    pub fn reset(&mut self) {
        self.shares.clear();
    }

    /// Get number of shares collected
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }
}

/// Privacy accountant using Rényi Differential Privacy
pub struct RenyiAccountant {
    /// Rényi divergence orders to track
    orders: Vec<f64>,
    /// Log of privacy loss moments
    log_moments: Vec<f64>,
    /// Target delta
    delta: f64,
}

impl RenyiAccountant {
    /// Create new Rényi accountant
    pub fn new(delta: f64) -> Self {
        // Standard orders for RDP
        let orders: Vec<f64> = (1..=64).map(|i| 1.0 + i as f64 / 10.0).collect();
        let log_moments = vec![0.0; orders.len()];

        Self {
            orders,
            log_moments,
            delta,
        }
    }

    /// Compose a Gaussian mechanism
    pub fn compose_gaussian(&mut self, sigma: f64, sensitivity: f64) {
        for (i, &order) in self.orders.iter().enumerate() {
            // RDP for Gaussian: alpha / (2 * sigma^2) for sensitivity 1
            let rdp = order * (sensitivity / sigma).powi(2) / 2.0;
            self.log_moments[i] += rdp;
        }
    }

    /// Get total epsilon spent
    pub fn get_epsilon(&self) -> f64 {
        // Convert RDP to (epsilon, delta)-DP
        self.orders.iter()
            .zip(self.log_moments.iter())
            .map(|(&order, &log_moment)| {
                log_moment + (order - 1.0).ln() / order - (order * self.delta).ln() / order
            })
            .fold(f64::INFINITY, f64::min)
    }

    /// Check if budget is exceeded
    pub fn exceeds_budget(&self, epsilon_budget: f64) -> bool {
        self.get_epsilon() > epsilon_budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gaussian_noise() {
        let dp = DifferentialPrivacy::new(1.0);
        let gradients = vec![1.0, 2.0, 3.0];

        let noisy = dp.add_noise(&gradients);

        assert_eq!(noisy.len(), 3);
        // With epsilon=1.0, noise should be moderate
        // Values should be different from original
        assert!(noisy.iter().zip(gradients.iter()).any(|(n, &o)| (*n - o).abs() > 0.001));
    }

    #[test]
    fn test_laplace_noise() {
        let dp = DifferentialPrivacy::new(1.0).with_laplace();
        let gradients = vec![1.0, 2.0, 3.0];

        let noisy = dp.add_noise(&gradients);

        assert_eq!(noisy.len(), 3);
    }

    #[test]
    fn test_gradient_clipping() {
        let dp = DifferentialPrivacy::new(1.0);
        let mut gradients = vec![3.0, 4.0]; // norm = 5

        dp.clip_gradients(&mut gradients, 1.0);

        let norm: f32 = gradients.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_privacy_budget() {
        let mut budget = PrivacyBudget::new(10.0, 1e-5);

        assert!(budget.can_spend(5.0, 1e-6));
        assert!(budget.spend(5.0, 1e-6));
        assert!((budget.remaining_epsilon() - 5.0).abs() < 0.01);

        assert!(!budget.can_spend(6.0, 0.0)); // Would exceed epsilon
        assert!(!budget.is_exhausted());
    }

    #[test]
    fn test_secure_aggregation_shares() {
        let sa = SecureAggregation::new(3);
        let gradients = vec![10.0, 20.0, 30.0];

        let shares = sa.create_shares(&gradients);

        assert_eq!(shares.len(), 3);

        // Sum of shares should equal original
        let mut sum = vec![0.0; 3];
        for share in &shares {
            for (i, &v) in share.iter().enumerate() {
                sum[i] += v;
            }
        }

        for (i, &s) in sum.iter().enumerate() {
            assert!((s - gradients[i]).abs() < 0.001);
        }
    }

    #[test]
    fn test_secure_aggregation() {
        let mut sa = SecureAggregation::with_threshold(3, 2);

        sa.add_share(vec![1.0, 2.0]);
        assert!(!sa.has_threshold());

        sa.add_share(vec![3.0, 4.0]);
        assert!(sa.has_threshold());

        let result = sa.aggregate().unwrap();
        assert_eq!(result, vec![4.0, 6.0]);
    }

    #[test]
    fn test_renyi_accountant() {
        let mut accountant = RenyiAccountant::new(1e-5);

        // Compose several mechanisms
        accountant.compose_gaussian(1.0, 1.0);
        accountant.compose_gaussian(1.0, 1.0);

        let epsilon = accountant.get_epsilon();
        assert!(epsilon > 0.0);
        assert!(epsilon < 10.0); // Reasonable bound
    }

    #[test]
    fn test_noise_scale() {
        let dp = DifferentialPrivacy::new(1.0);
        let scale = dp.noise_scale();
        assert!(scale > 0.0);

        // Higher epsilon = lower noise
        let dp_high = DifferentialPrivacy::new(10.0);
        assert!(dp_high.noise_scale() < scale);
    }
}
