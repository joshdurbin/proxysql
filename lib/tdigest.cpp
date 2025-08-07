#include "tdigest.h"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <limits>
#include <string>
#include <sstream>
#include <thread>

// TDigest Implementation - ClickHouse-inspired production version

TDigest::TDigest(double compression, size_t max_centroids, size_t max_unmerged)
    : total_weight_(0.0), cached_merged_valid_(false), cached_unmerged_size_(0) {
    // Validate and set parameters with sensible defaults
    compression_ = (compression > 0.0) ? compression : DEFAULT_COMPRESSION;
    max_centroids_ = (max_centroids > 0) ? max_centroids : DEFAULT_MAX_CENTROIDS;
    max_unmerged_ = (max_unmerged > 0) ? max_unmerged : DEFAULT_MAX_UNMERGED;
    
    // Ensure max_centroids is reasonable relative to compression
    if (max_centroids_ < static_cast<size_t>(compression_ * 2)) {
        max_centroids_ = static_cast<size_t>(compression_ * 2);
    }
    
    centroids_.reserve(max_centroids_);
    unmerged_.reserve(max_unmerged_);
}

TDigest::TDigest(TDigest&& other) noexcept
    : centroids_(std::move(other.centroids_)),
      unmerged_(std::move(other.unmerged_)),
      total_weight_(other.total_weight_),
      compression_(other.compression_),
      max_unmerged_(other.max_unmerged_),
      max_centroids_(other.max_centroids_),
      cached_merged_(std::move(other.cached_merged_)),
      cached_merged_valid_(other.cached_merged_valid_),
      cached_unmerged_size_(other.cached_unmerged_size_) {
    // mutex_ is default constructed (not moved)
    other.total_weight_ = 0.0;
    other.cached_merged_valid_ = false;
    other.cached_unmerged_size_ = 0;
}

TDigest& TDigest::operator=(TDigest&& other) noexcept {
    if (this != &other) {
        // Use std::lock to avoid deadlock - acquire both mutexes atomically
        std::lock(mutex_, other.mutex_);
        std::lock_guard<std::mutex> lock(mutex_, std::adopt_lock);
        std::lock_guard<std::mutex> other_lock(other.mutex_, std::adopt_lock);
        
        centroids_ = std::move(other.centroids_);
        unmerged_ = std::move(other.unmerged_);
        total_weight_ = other.total_weight_;
        compression_ = other.compression_;
        max_unmerged_ = other.max_unmerged_;
        max_centroids_ = other.max_centroids_;
        cached_merged_ = std::move(other.cached_merged_);
        cached_merged_valid_ = other.cached_merged_valid_;
        cached_unmerged_size_ = other.cached_unmerged_size_;
        
        other.total_weight_ = 0.0;
        other.cached_merged_valid_ = false;
        other.cached_unmerged_size_ = 0;
    }
    return *this;
}

void TDigest::add(double value, double weight) {
    if (weight <= 0.0 || std::isnan(value) || std::isinf(value)) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Add to unmerged first for efficiency
    unmerged_.emplace_back(value, weight);
    total_weight_ += weight;
    
    // Invalidate cache when adding new data
    cached_merged_valid_ = false;
    
    // Compress when unmerged buffer is full
    if (unmerged_.size() >= max_unmerged_) {
        merge_unmerged();
        if (centroids_.size() >= compression_ * 2 && total_weight_ > 10.0) {  // Only compress with sufficient data
            compress();
        }
    }
}

void TDigest::add_batch(const std::vector<double>& values) {
    if (values.empty()) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (double value : values) {
        if (!std::isnan(value) && !std::isinf(value)) {
            unmerged_.emplace_back(value, 1.0);
            total_weight_ += 1.0;
        }
    }
    
    // Invalidate cache when adding new data
    cached_merged_valid_ = false;
    
    merge_unmerged();
    if (centroids_.size() >= compression_ * 2 && total_weight_ > 10.0) {  // Only compress with sufficient data
        compress();
    }
}

void TDigest::merge_unmerged() {
    if (unmerged_.empty()) return;
    
    // Sort unmerged data
    std::sort(unmerged_.begin(), unmerged_.end());
    
    // Merge with existing centroids
    std::vector<Centroid> merged;
    merged.reserve(centroids_.size() + unmerged_.size());
    
    size_t i = 0, j = 0;
    while (i < centroids_.size() && j < unmerged_.size()) {
        if (centroids_[i].mean <= unmerged_[j].mean) {
            merged.push_back(centroids_[i++]);
        } else {
            merged.push_back(unmerged_[j++]);
        }
    }
    
    while (i < centroids_.size()) {
        merged.push_back(centroids_[i++]);
    }
    while (j < unmerged_.size()) {
        merged.push_back(unmerged_[j++]);
    }
    
    centroids_ = std::move(merged);
    unmerged_.clear();
}

void TDigest::compress() {
    if (centroids_.empty()) return;
    
    std::sort(centroids_.begin(), centroids_.end());
    
    std::vector<Centroid> compressed;
    compressed.reserve(max_centroids_);
    
    double so_far = 0.0;
    
    for (const auto& centroid : centroids_) {
        double q0 = so_far / total_weight_;
        double q1 = (so_far + centroid.weight) / total_weight_;
        
        // ClickHouse-inspired k-size calculation with improved numerical stability
        // Clamp q values to avoid asin domain errors
        q0 = std::max(0.0, std::min(1.0, q0));
        q1 = std::max(0.0, std::min(1.0, q1));
        
        // Compute asin arguments with better numerical stability
        // Use sin⁻¹ transformation: asin(2q - 1) where q ∈ [0,1] maps to [-π/2, π/2]
        double asin_arg0 = 2.0 * q0 - 1.0;
        double asin_arg1 = 2.0 * q1 - 1.0;
        
        // Numerical stability: for values very close to ±1, use Taylor approximation
        // asin(x) ≈ π/2 - sqrt(2) * sqrt(1-x) for x close to 1
        // asin(x) ≈ -π/2 + sqrt(2) * sqrt(1+x) for x close to -1
        double k0, k1;
        
        if (asin_arg0 > 0.999999) {
            k0 = compression_ * (M_PI_2 - std::sqrt(2.0 * (1.0 - asin_arg0))) / M_PI;
        } else if (asin_arg0 < -0.999999) {
            k0 = compression_ * (-M_PI_2 + std::sqrt(2.0 * (1.0 + asin_arg0))) / M_PI;
        } else {
            k0 = compression_ * std::asin(asin_arg0) / M_PI;
        }
        
        if (asin_arg1 > 0.999999) {
            k1 = compression_ * (M_PI_2 - std::sqrt(2.0 * (1.0 - asin_arg1))) / M_PI;
        } else if (asin_arg1 < -0.999999) {
            k1 = compression_ * (-M_PI_2 + std::sqrt(2.0 * (1.0 + asin_arg1))) / M_PI;
        } else {
            k1 = compression_ * std::asin(asin_arg1) / M_PI;
        }
        double k_limit = std::max(k1 - k0, 1.0 / compression_) * total_weight_;
        
        // Try to merge with previous centroid if weight constraints allow
        if (!compressed.empty() && 
            compressed.back().weight + centroid.weight <= k_limit) {
            // Merge with previous centroid
            auto& last = compressed.back();
            double new_weight = last.weight + centroid.weight;
            last.mean = (last.mean * last.weight + centroid.mean * centroid.weight) / new_weight;
            last.weight = new_weight;
        } else {
            // Create new centroid
            compressed.push_back(centroid);
        }
        
        so_far += centroid.weight;
    }
    
    centroids_ = std::move(compressed);
}

double TDigest::interpolate(double x, double x0, double x1) const {
    return (x - x0) / (x1 - x0);
}

const std::vector<TDigest::Centroid>& TDigest::get_merged_view() const {
    // Check if cache is still valid
    if (cached_merged_valid_ && cached_unmerged_size_ == unmerged_.size()) {
        return cached_merged_;
    }
    
    // Cache is invalid, rebuild it
    cached_merged_.clear();
    
    if (unmerged_.empty()) {
        cached_merged_ = centroids_;
    } else {
        // Sort unmerged data
        std::vector<Centroid> sorted_unmerged = unmerged_;
        std::sort(sorted_unmerged.begin(), sorted_unmerged.end());
        
        // Merge centroids and unmerged data
        cached_merged_.reserve(centroids_.size() + sorted_unmerged.size());
        
        size_t i = 0, j = 0;
        while (i < centroids_.size() && j < sorted_unmerged.size()) {
            if (centroids_[i].mean <= sorted_unmerged[j].mean) {
                cached_merged_.push_back(centroids_[i++]);
            } else {
                cached_merged_.push_back(sorted_unmerged[j++]);
            }
        }
        
        while (i < centroids_.size()) {
            cached_merged_.push_back(centroids_[i++]);
        }
        while (j < sorted_unmerged.size()) {
            cached_merged_.push_back(sorted_unmerged[j++]);
        }
    }
    
    cached_merged_valid_ = true;
    cached_unmerged_size_ = unmerged_.size();
    
    return cached_merged_;
}

double TDigest::quantile(double q) const {
    // Clamp quantile to valid range instead of returning NaN
    if (q < 0.0) q = 0.0;
    if (q > 1.0) q = 1.0;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Use optimized cached merged view
    const std::vector<Centroid>& working_centroids = get_merged_view();
    
    if (working_centroids.empty() || total_weight_ <= 0.0) {
        return 0.0; // Return 0 instead of NaN for empty data
    }
    
    if (working_centroids.size() == 1) {
        double value = working_centroids[0].mean;
        return std::isfinite(value) && value >= 0.0 ? value : 0.0;
    }
    
    double target = q * total_weight_;
    
    if (target <= working_centroids[0].weight / 2.0) {
        double value = working_centroids[0].mean;
        return std::isfinite(value) && value >= 0.0 ? value : 0.0;
    }
    
    if (target >= total_weight_ - working_centroids.back().weight / 2.0) {
        double value = working_centroids.back().mean;
        return std::isfinite(value) && value >= 0.0 ? value : 0.0;
    }
    
    double so_far = 0.0;
    
    for (size_t i = 0; i < working_centroids.size(); ++i) {
        double next_so_far = so_far + working_centroids[i].weight;
        
        if (target <= next_so_far) {
            if (i == 0) {
                double value = working_centroids[0].mean;
                return std::isfinite(value) && value >= 0.0 ? value : 0.0;
            }
            
            // Improved interpolation using weighted averages
            double left_weight = working_centroids[i-1].weight;
            double right_weight = working_centroids[i].weight;
            double left_pos = so_far - left_weight / 2.0;
            double right_pos = next_so_far - right_weight / 2.0;
            
            if (target <= left_pos + left_weight / 2.0) {
                double value = working_centroids[i-1].mean;
                return std::isfinite(value) && value >= 0.0 ? value : 0.0;
            }
            if (target >= right_pos - right_weight / 2.0) {
                double value = working_centroids[i].mean;
                return std::isfinite(value) && value >= 0.0 ? value : 0.0;
            }
            
            // Linear interpolation with better boundary handling and zero-division protection
            double denominator = right_pos - right_weight / 2.0 - left_pos - left_weight / 2.0;
            double fraction = 0.5; // Default to midpoint if division by zero
            
            if (std::abs(denominator) > 1e-15) { // Avoid division by zero
                fraction = (target - left_pos - left_weight / 2.0) / denominator;
                fraction = std::max(0.0, std::min(1.0, fraction));
            }
            
            double interpolated = working_centroids[i-1].mean + 
                                 (working_centroids[i].mean - working_centroids[i-1].mean) * fraction;
            return std::isfinite(interpolated) && interpolated >= 0.0 ? interpolated : 0.0;
        }
        
        so_far = next_so_far;
    }
    
    double result = working_centroids.back().mean;
    return std::isfinite(result) && result >= 0.0 ? result : 0.0;
}

std::vector<double> TDigest::quantiles(const std::vector<double>& quantiles) const {
    std::vector<double> result;
    result.reserve(quantiles.size());
    
    for (double q : quantiles) {
        result.push_back(quantile(q));
    }
    
    return result;
}

double TDigest::cdf(double x) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Use optimized cached merged view
    const std::vector<Centroid>& working_centroids = get_merged_view();
    
    if (working_centroids.empty()) {
        return 0.0;
    }
    
    if (x <= working_centroids.front().mean) {
        return 0.0;
    }
    if (x >= working_centroids.back().mean) {
        return 1.0;
    }
    
    double so_far = 0.0;
    
    for (size_t i = 0; i < working_centroids.size(); ++i) {
        if (x <= working_centroids[i].mean) {
            if (i == 0) {
                return working_centroids[0].weight / (2.0 * total_weight_);
            }
            
            // Linear interpolation
            double delta = (x - working_centroids[i-1].mean) / (working_centroids[i].mean - working_centroids[i-1].mean);
            return (so_far - working_centroids[i-1].weight / 2.0 + 
                    delta * (working_centroids[i-1].weight / 2.0 + working_centroids[i].weight / 2.0)) / total_weight_;
        }
        so_far += working_centroids[i].weight;
    }
    
    return 1.0;
}

double TDigest::count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_weight_;
}

size_t TDigest::centroids_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return centroids_.size();
}

size_t TDigest::unmerged_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return unmerged_.size();
}

double TDigest::min() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (centroids_.empty() && unmerged_.empty()) {
        return std::numeric_limits<double>::quiet_NaN();
    }
    
    double min_val = std::numeric_limits<double>::infinity();
    
    if (!centroids_.empty()) {
        min_val = std::min(min_val, centroids_.front().mean);
    }
    
    if (!unmerged_.empty()) {
        auto min_unmerged = std::min_element(unmerged_.begin(), unmerged_.end());
        min_val = std::min(min_val, min_unmerged->mean);
    }
    
    return min_val;
}

double TDigest::max() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (centroids_.empty() && unmerged_.empty()) {
        return std::numeric_limits<double>::quiet_NaN();
    }
    
    double max_val = -std::numeric_limits<double>::infinity();
    
    if (!centroids_.empty()) {
        max_val = std::max(max_val, centroids_.back().mean);
    }
    
    if (!unmerged_.empty()) {
        auto max_unmerged = std::max_element(unmerged_.begin(), unmerged_.end());
        max_val = std::max(max_val, max_unmerged->mean);
    }
    
    return max_val;
}

void TDigest::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    centroids_.clear();
    unmerged_.clear();
    total_weight_ = 0.0;
    
    // Invalidate cache
    cached_merged_valid_ = false;
    cached_merged_.clear();
    cached_unmerged_size_ = 0;
}

void TDigest::merge(const TDigest& other) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::lock_guard<std::mutex> other_lock(other.mutex_);
    
    // Add all centroids from other digest to unmerged
    for (const auto& centroid : other.centroids_) {
        unmerged_.push_back(centroid);
        total_weight_ += centroid.weight;
    }
    
    for (const auto& centroid : other.unmerged_) {
        unmerged_.push_back(centroid);
        total_weight_ += centroid.weight;
    }
    
    merge_unmerged();
    if (centroids_.size() > max_centroids_) {
        compress();
    }
}

void TDigest::force_compress() {
    std::lock_guard<std::mutex> lock(mutex_);
    merge_unmerged();
    compress();
}

bool TDigest::empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return centroids_.empty() && unmerged_.empty();
}

// CommandLatencyTracker Implementation

CommandLatencyTracker::CommandLatencyTracker(size_t num_commands) 
    : command_stats_(num_commands), enabled_(true) {
    // Validate num_commands parameter
    if (num_commands == 0 || num_commands > 1000) {
        // Use safe default if invalid
        command_stats_.resize(64);
    }
    
    // Default quantiles
    configured_quantiles_ = {0.5, 0.9, 0.95, 0.99};
}

void CommandLatencyTracker::record_latency(size_t command_type, uint64_t latency_us) {
    if (!enabled_ || command_type >= command_stats_.size()) {
        return;
    }
    
    // Validate latency value - reject extremely large values that could indicate bugs
    if (latency_us > 3600000000ULL) { // > 1 hour in microseconds
        return;
    }
    
    // Debug: Log latencies (sample every 10000th to avoid spam)
    static std::atomic<uint64_t> debug_counter{0};
    static std::atomic<uint64_t> zero_counter{0};
    uint64_t sample_num = debug_counter.fetch_add(1);
    if (sample_num % 10000 == 0) {
        if (latency_us == 0) {
            uint64_t zero_count = zero_counter.fetch_add(1);
            fprintf(stderr, "MySQL t-digest: Recording ZERO latency for command %zu (zeros: %llu/total: %llu)\n", 
                    command_type, zero_count, sample_num);
        } else {
            fprintf(stderr, "MySQL t-digest: Recording latency %llu us for command %zu (sample %llu)\n", 
                    latency_us, command_type, sample_num);
        }
    } else if (latency_us == 0) {
        zero_counter.fetch_add(1);
    }
    
    auto& stats = command_stats_[command_type];
    
    // Update atomic counters
    stats.query_count.fetch_add(1, std::memory_order_relaxed);
    stats.total_time_us.fetch_add(latency_us, std::memory_order_relaxed);
    
    // Update min/max atomically with bounded retry to prevent infinite loops
    uint64_t current_min = stats.min_time_us.load(std::memory_order_relaxed);
    for (int retry = 0; retry < 10 && latency_us < current_min; ++retry) {
        if (stats.min_time_us.compare_exchange_weak(current_min, latency_us, std::memory_order_relaxed)) {
            break;
        }
        // Exponential backoff to reduce contention
        if (retry > 3) {
            std::this_thread::yield();
        }
    }
    
    uint64_t current_max = stats.max_time_us.load(std::memory_order_relaxed);
    for (int retry = 0; retry < 10 && latency_us > current_max; ++retry) {
        if (stats.max_time_us.compare_exchange_weak(current_max, latency_us, std::memory_order_relaxed)) {
            break;
        }
        // Exponential backoff to reduce contention
        if (retry > 3) {
            std::this_thread::yield();
        }
    }
    
    // Add to t-digest (already thread-safe)
    stats.digest.add(static_cast<double>(latency_us));
}

double CommandLatencyTracker::get_quantile(size_t command_type, double quantile) const {
    if (command_type >= command_stats_.size() || quantile < 0.0 || quantile > 1.0) {
        return std::numeric_limits<double>::quiet_NaN();
    }
    
    return command_stats_[command_type].digest.quantile(quantile);
}

std::vector<double> CommandLatencyTracker::get_quantiles(size_t command_type, 
                                                        const std::vector<double>& quantiles) const {
    if (command_type >= command_stats_.size()) {
        return std::vector<double>(quantiles.size(), std::numeric_limits<double>::quiet_NaN());
    }
    
    // Validate all quantiles are in valid range
    for (double q : quantiles) {
        if (q < 0.0 || q > 1.0) {
            return std::vector<double>(quantiles.size(), std::numeric_limits<double>::quiet_NaN());
        }
    }
    
    return command_stats_[command_type].digest.quantiles(quantiles);
}

uint64_t CommandLatencyTracker::get_query_count(size_t command_type) const {
    if (command_type >= command_stats_.size()) {
        return 0;
    }
    
    return command_stats_[command_type].query_count.load(std::memory_order_relaxed);
}

uint64_t CommandLatencyTracker::get_total_time_us(size_t command_type) const {
    if (command_type >= command_stats_.size()) {
        return 0;
    }
    
    return command_stats_[command_type].total_time_us.load(std::memory_order_relaxed);
}

uint64_t CommandLatencyTracker::get_min_time_us(size_t command_type) const {
    if (command_type >= command_stats_.size()) {
        return 0;
    }
    
    uint64_t min_val = command_stats_[command_type].min_time_us.load(std::memory_order_relaxed);
    return (min_val == std::numeric_limits<uint64_t>::max()) ? 0 : min_val;
}

uint64_t CommandLatencyTracker::get_max_time_us(size_t command_type) const {
    if (command_type >= command_stats_.size()) {
        return 0;
    }
    
    return command_stats_[command_type].max_time_us.load(std::memory_order_relaxed);
}

double CommandLatencyTracker::get_avg_time_us(size_t command_type) const {
    if (command_type >= command_stats_.size()) {
        return 0.0;
    }
    
    const auto& stats = command_stats_[command_type];
    uint64_t count = stats.query_count.load(std::memory_order_relaxed);
    uint64_t total = stats.total_time_us.load(std::memory_order_relaxed);
    
    return (count > 0) ? static_cast<double>(total) / count : 0.0;
}

void CommandLatencyTracker::reset() {
    std::lock_guard<std::mutex> lock(global_mutex_);
    
    for (auto& stats : command_stats_) {
        stats.query_count.store(0, std::memory_order_relaxed);
        stats.total_time_us.store(0, std::memory_order_relaxed);
        stats.min_time_us.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
        stats.max_time_us.store(0, std::memory_order_relaxed);
        stats.digest.clear();
    }
}

void CommandLatencyTracker::reset_command(size_t command_type) {
    if (command_type >= command_stats_.size()) {
        return;
    }
    
    auto& stats = command_stats_[command_type];
    stats.query_count.store(0, std::memory_order_relaxed);
    stats.total_time_us.store(0, std::memory_order_relaxed);
    stats.min_time_us.store(std::numeric_limits<uint64_t>::max(), std::memory_order_relaxed);
    stats.max_time_us.store(0, std::memory_order_relaxed);
    stats.digest.clear();
}

size_t CommandLatencyTracker::command_count() const {
    return command_stats_.size();
}

void CommandLatencyTracker::force_compress_all() {
    std::lock_guard<std::mutex> lock(global_mutex_);
    
    for (auto& stats : command_stats_) {
        stats.digest.force_compress();
    }
}

void CommandLatencyTracker::update_configuration(bool enabled, const char* quantiles_str, 
                                                int compression, int max_centroids, int max_unmerged) {
    std::lock_guard<std::mutex> lock(global_mutex_);
    
    enabled_ = enabled;
    
    // Validate configuration parameters
    if (compression < 100) {
        compression = 10000; // Default compression * 100
    }
    if (max_centroids < 64) {
        max_centroids = 2048; // Default max centroids
    }
    if (max_unmerged < 10) {
        max_unmerged = 100; // Default max unmerged
    }
    
    // Validate parameter relationships
    double compression_factor = compression / 100.0;
    if (static_cast<size_t>(compression_factor * 2) > max_centroids) {
        // Adjust max_centroids to be at least 2x compression for optimal performance
        max_centroids = static_cast<int>(compression_factor * 2);
    }
    
    // Parse quantiles string with improved validation
    configured_quantiles_.clear();
    if (quantiles_str && strlen(quantiles_str) > 0) {
        std::string str(quantiles_str);
        std::stringstream ss(str);
        std::string item;
        
        while (std::getline(ss, item, ',')) {
            // Trim whitespace
            item.erase(0, item.find_first_not_of(" \t"));
            item.erase(item.find_last_not_of(" \t") + 1);
            
            if (!item.empty()) {
                try {
                    // More strict validation for quantile parsing
                    size_t pos;
                    double quantile = std::stod(item, &pos);
                    
                    // Ensure entire string was consumed (no trailing garbage)
                    if (pos == item.length() && quantile >= 0.0 && quantile <= 1.0) {
                        // Check for duplicates
                        bool duplicate = false;
                        for (double existing : configured_quantiles_) {
                            if (std::abs(existing - quantile) < 1e-6) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            configured_quantiles_.push_back(quantile);
                        }
                    }
                } catch (...) {
                    // Skip invalid quantiles
                }
            }
        }
        
        // Sort quantiles for consistent ordering
        std::sort(configured_quantiles_.begin(), configured_quantiles_.end());
    }
    
    // Ensure we have at least default quantiles if parsing failed
    if (configured_quantiles_.empty()) {
        configured_quantiles_ = {0.5, 0.9, 0.95, 0.99};
    }
    
    // Update t-digest parameters for all command stats
    for (auto& stats : command_stats_) {
        // Create new t-digest with validated parameters
        stats.digest = TDigest(compression_factor, max_centroids, max_unmerged);
    }
}

bool CommandLatencyTracker::is_enabled() const {
    return enabled_;
}

std::vector<double> CommandLatencyTracker::get_configured_quantiles() const {
    std::lock_guard<std::mutex> lock(global_mutex_);
    return configured_quantiles_;
}