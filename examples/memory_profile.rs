//! Memory profiling utility for WAF engine
//!
//! Measures steady-state memory usage for different configurations.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use zentinel_agent_waf::{WafConfig, WafEngine};

fn separator(char: char, width: usize) {
    println!(
        "{}",
        std::iter::repeat(char).take(width).collect::<String>()
    );
}

// Custom allocator to track memory usage
struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if !ret.is_null() {
            let size = layout.size();
            let current = ALLOCATED.fetch_add(size, Ordering::SeqCst) + size;
            // Update peak
            let mut peak = PEAK.load(Ordering::SeqCst);
            while current > peak {
                match PEAK.compare_exchange_weak(peak, current, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break,
                    Err(p) => peak = p,
                }
            }
        }
        ret
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

fn bytes_to_mb(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn main() {
    println!("WAF Engine Memory Profile");
    separator('=', 60);
    println!();

    // Baseline before any WAF creation
    let baseline = ALLOCATED.load(Ordering::SeqCst);
    println!(
        "Baseline memory (before WAF): {:.2} MB",
        bytes_to_mb(baseline)
    );
    println!();

    // Test different paranoia levels
    println!("Memory by Paranoia Level:");
    separator('-', 40);

    for level in 1..=4 {
        // Reset peak for this measurement
        PEAK.store(ALLOCATED.load(Ordering::SeqCst), Ordering::SeqCst);

        let before = ALLOCATED.load(Ordering::SeqCst);

        let config = WafConfig {
            paranoia_level: level,
            ..Default::default()
        };
        let engine = WafEngine::new(config).expect("Failed to create engine");

        let after = ALLOCATED.load(Ordering::SeqCst);
        let peak = PEAK.load(Ordering::SeqCst);
        let engine_mem = after - before;

        println!(
            "  Level {}: {:.2} MB (peak during creation: {:.2} MB)",
            level,
            bytes_to_mb(engine_mem),
            bytes_to_mb(peak - before)
        );

        // Keep engine alive for accurate measurement
        std::hint::black_box(&engine);
        drop(engine);
    }

    println!();
    println!("Full Feature Memory Profile:");
    separator('-', 40);

    // Test with all features enabled
    let before = ALLOCATED.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);

    let config = WafConfig {
        paranoia_level: 4,
        api_security: zentinel_agent_waf::config::ApiSecurityConfig {
            graphql_enabled: true,
            json_enabled: true,
            jwt_enabled: true,
            ..Default::default()
        },
        sensitive_data: zentinel_agent_waf::config::SensitiveDataDetectionConfig {
            enabled: true,
            credit_card_detection: true,
            ssn_detection: true,
            api_key_detection: true,
            private_key_detection: true,
        },
        ..Default::default()
    };
    let full_engine = WafEngine::new(config).expect("Failed to create engine");

    let after = ALLOCATED.load(Ordering::SeqCst);
    let peak = PEAK.load(Ordering::SeqCst);

    println!(
        "  All features (PL4): {:.2} MB steady state",
        bytes_to_mb(after - before)
    );
    println!("  Peak during init:   {:.2} MB", bytes_to_mb(peak - before));

    // Simulate request processing
    println!();
    println!("Memory During Request Processing:");
    separator('-', 40);

    let headers: HashMap<String, Vec<String>> = [
        ("User-Agent".to_string(), vec!["Mozilla/5.0".to_string()]),
        ("Cookie".to_string(), vec!["session=abc123".to_string()]),
    ]
    .into_iter()
    .collect();

    let before_requests = ALLOCATED.load(Ordering::SeqCst);
    PEAK.store(before_requests, Ordering::SeqCst);

    // Process many requests
    for i in 0..10000 {
        let query = format!("search=test{}&page={}", i, i % 100);
        let _ = full_engine.check_request("/api/search", Some(&query), &headers);
    }

    let after_requests = ALLOCATED.load(Ordering::SeqCst);
    let peak_requests = PEAK.load(Ordering::SeqCst);

    println!(
        "  After 10k requests:  {:.2} MB delta",
        bytes_to_mb(after_requests.saturating_sub(before_requests))
    );
    println!(
        "  Peak during requests: {:.2} MB above baseline",
        bytes_to_mb(peak_requests.saturating_sub(before_requests))
    );

    // Keep engine alive
    std::hint::black_box(&full_engine);

    println!();
    println!("Summary:");
    separator('=', 60);
    let total = ALLOCATED.load(Ordering::SeqCst);
    let total_peak = PEAK.load(Ordering::SeqCst);
    println!("  Total current allocation: {:.2} MB", bytes_to_mb(total));
    println!(
        "  Total peak allocation:    {:.2} MB",
        bytes_to_mb(total_peak)
    );
    println!();

    let target = 50.0;
    if bytes_to_mb(total_peak) < target {
        println!(
            "  STATUS: PASS - Peak memory {:.2} MB < {:.0} MB target",
            bytes_to_mb(total_peak),
            target
        );
    } else {
        println!(
            "  STATUS: FAIL - Peak memory {:.2} MB >= {:.0} MB target",
            bytes_to_mb(total_peak),
            target
        );
    }
}
