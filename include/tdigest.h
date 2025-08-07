#ifndef __PROXYSQL_TDIGEST_H
#define __PROXYSQL_TDIGEST_H

#include <vector>
#include <algorithm>
#include <cmath>
#include <mutex>
#include <atomic>
#include <limits>
#include <cstring>

/**
 * @brief ClickHouse-inspired production-ready t-digest implementation for ProxySQL
 * 
 * This implementation is based on ClickHouse's t-digest algorithm with optimizations
 * for bounded memory usage, numerical stability, and thread safety.
 * 
 * Features:
 * - Bounded memory usage with configurable compression
 * - Thread-safe operations
 * - Fast quantile estimation, especially accurate at extremes
 * - Handles edge cases (infinities, NaN, empty data)
 * - Optimized for high-throughput query processing
 */
class TDigest {
public:
    struct Centroid {
        double mean;
        double weight;
        
        Centroid() : mean(0.0), weight(0.0) {}
        Centroid(double m, double w) : mean(m), weight(w) {}
        
        bool operator<(const Centroid& other) const {
            return mean < other.mean;
        }
        
        void add(double value, double w = 1.0) {
            if (weight == 0.0) {
                mean = value;
                weight = w;
            } else {
                weight += w;
                mean += w * (value - mean) / weight;
            }
        }
    };

private:
    std::vector<Centroid> centroids_;
    std::vector<Centroid> unmerged_;
    
    double total_weight_;
    double compression_;
    size_t max_unmerged_;
    size_t max_centroids_;
    
    mutable std::mutex mutex_;
    
    // Performance optimization: cached merged state
    mutable std::vector<Centroid> cached_merged_;
    mutable bool cached_merged_valid_;
    mutable size_t cached_unmerged_size_;
    
    // ClickHouse-inspired compression parameters
    static constexpr double DEFAULT_COMPRESSION = 100.0;
    static constexpr size_t DEFAULT_MAX_CENTROIDS = 2048;
    static constexpr size_t DEFAULT_MAX_UNMERGED = 100;
    
    void compress();
    void merge_unmerged();
    double interpolate(double x, double x0, double x1) const;
    const std::vector<Centroid>& get_merged_view() const;
    
public:
    /**
     * @brief Construct a new TDigest with ClickHouse-inspired parameters
     * @param compression Compression factor (default: 100.0, higher = more accurate)
     * @param max_centroids Maximum number of centroids (default: 2048)
     * @param max_unmerged Maximum unmerged points before compression (default: 100)
     */
    explicit TDigest(double compression = DEFAULT_COMPRESSION, 
                     size_t max_centroids = DEFAULT_MAX_CENTROIDS,
                     size_t max_unmerged = DEFAULT_MAX_UNMERGED);
    
    // Move constructor
    TDigest(TDigest&& other) noexcept;
    
    // Move assignment operator
    TDigest& operator=(TDigest&& other) noexcept;
    
    // Delete copy constructor and copy assignment operator
    TDigest(const TDigest&) = delete;
    TDigest& operator=(const TDigest&) = delete;
    
    /**
     * @brief Add a single value to the digest
     * @param value The value to add
     * @param weight The weight of the value (default: 1.0)
     */
    void add(double value, double weight = 1.0);
    
    /**
     * @brief Add multiple values efficiently
     * @param values Vector of values to add
     */
    void add_batch(const std::vector<double>& values);
    
    /**
     * @brief Get the approximate quantile
     * @param q Quantile between 0.0 and 1.0
     * @return Approximate value at the given quantile, or NaN if invalid
     */
    double quantile(double q) const;
    
    /**
     * @brief Get multiple quantiles efficiently
     * @param quantiles Vector of quantiles to compute (between 0.0 and 1.0)
     * @return Vector of approximate values at the given quantiles
     */
    std::vector<double> quantiles(const std::vector<double>& quantiles) const;
    
    /**
     * @brief Get the cumulative distribution function value
     * @param x The value at which to evaluate the CDF
     * @return CDF value between 0.0 and 1.0
     */
    double cdf(double x) const;
    
    /**
     * @brief Get the total number of values added
     */
    double count() const;
    
    /**
     * @brief Get the current number of centroids
     */
    size_t centroids_count() const;
    
    /**
     * @brief Get the number of unmerged points
     */
    size_t unmerged_count() const;
    
    /**
     * @brief Get minimum value seen (approximate)
     */
    double min() const;
    
    /**
     * @brief Get maximum value seen (approximate)
     */
    double max() const;
    
    /**
     * @brief Reset the digest to empty state
     */
    void clear();
    
    /**
     * @brief Merge another digest into this one
     * @param other The digest to merge
     */
    void merge(const TDigest& other);
    
    /**
     * @brief Force compression of unmerged data
     */
    void force_compress();
    
    /**
     * @brief Check if digest is empty
     */
    bool empty() const;
    
    /**
     * @brief Get compression factor
     */
    double get_compression() const { return compression_; }
};

/**
 * @brief Command-specific latency tracker using ClickHouse-inspired t-digest
 * 
 * Tracks latency percentiles per MySQL command type with bounded memory usage.
 * Thread-safe and designed for high-throughput query processing.
 */
class CommandLatencyTracker {
private:
    struct CommandStats {
        TDigest digest;
        std::atomic<uint64_t> query_count{0};
        std::atomic<uint64_t> total_time_us{0};
        std::atomic<uint64_t> min_time_us{std::numeric_limits<uint64_t>::max()};
        std::atomic<uint64_t> max_time_us{0};
        
        CommandStats() : digest(100.0, 2048, 100) {} // ClickHouse-inspired params
        
        // Delete copy constructor and copy assignment to match TDigest
        CommandStats(const CommandStats&) = delete;
        CommandStats& operator=(const CommandStats&) = delete;
        
        // Allow move construction and assignment
        CommandStats(CommandStats&& other) noexcept
            : digest(std::move(other.digest)),
              query_count(other.query_count.load()),
              total_time_us(other.total_time_us.load()),
              min_time_us(other.min_time_us.load()),
              max_time_us(other.max_time_us.load()) {}
        
        CommandStats& operator=(CommandStats&& other) noexcept {
            if (this != &other) {
                digest = std::move(other.digest);
                query_count.store(other.query_count.load());
                total_time_us.store(other.total_time_us.load());
                min_time_us.store(other.min_time_us.load());
                max_time_us.store(other.max_time_us.load());
            }
            return *this;
        }
    };
    
    // Array indexed by MYSQL_COM_QUERY_command enum values
    std::vector<CommandStats> command_stats_;
    mutable std::mutex global_mutex_;
    
    // Configuration
    bool enabled_;
    std::vector<double> configured_quantiles_;
    
public:
    /**
     * @brief Initialize tracker for specified number of command types
     * @param num_commands Maximum command type index + 1
     */
    explicit CommandLatencyTracker(size_t num_commands);
    
    /**
     * @brief Record a query latency for a command type
     * @param command_type The command type index
     * @param latency_us Query latency in microseconds
     */
    void record_latency(size_t command_type, uint64_t latency_us);
    
    /**
     * @brief Get latency quantile for a command type
     * @param command_type The command type index
     * @param quantile Quantile between 0.0 and 1.0 (e.g., 0.95 for p95)
     * @return Latency in microseconds at the given quantile
     */
    double get_quantile(size_t command_type, double quantile) const;
    
    /**
     * @brief Get multiple quantiles for a command type
     * @param command_type The command type index
     * @param quantiles Vector of quantiles to compute
     * @return Vector of latencies in microseconds
     */
    std::vector<double> get_quantiles(size_t command_type, const std::vector<double>& quantiles) const;
    
    /**
     * @brief Get query count for a command type
     * @param command_type The command type index
     */
    uint64_t get_query_count(size_t command_type) const;
    
    /**
     * @brief Get total time for a command type
     * @param command_type The command type index
     */
    uint64_t get_total_time_us(size_t command_type) const;
    
    /**
     * @brief Get minimum latency for a command type
     * @param command_type The command type index
     */
    uint64_t get_min_time_us(size_t command_type) const;
    
    /**
     * @brief Get maximum latency for a command type
     * @param command_type The command type index
     */
    uint64_t get_max_time_us(size_t command_type) const;
    
    /**
     * @brief Get average latency for a command type
     * @param command_type The command type index
     */
    double get_avg_time_us(size_t command_type) const;
    
    /**
     * @brief Reset stats for all command types
     */
    void reset();
    
    /**
     * @brief Reset stats for a specific command type
     * @param command_type The command type index
     */
    void reset_command(size_t command_type);
    
    /**
     * @brief Get the number of tracked command types
     */
    size_t command_count() const;
    
    /**
     * @brief Force compression for all command types
     */
    void force_compress_all();
    
    /**
     * @brief Update t-digest configuration from ProxySQL variables
     * @param enabled Enable/disable t-digest tracking
     * @param quantiles_str Comma-separated quantiles string (e.g., "0.5,0.95,0.99")
     * @param compression Compression factor (stored as int * 100)
     * @param max_centroids Maximum number of centroids
     * @param max_unmerged Maximum unmerged buffer size
     */
    void update_configuration(bool enabled, const char* quantiles_str, 
                            int compression, int max_centroids, int max_unmerged);
    
    /**
     * @brief Check if t-digest tracking is enabled
     */
    bool is_enabled() const;
    
    /**
     * @brief Get currently configured quantiles
     */
    std::vector<double> get_configured_quantiles() const;
};

#endif /* __PROXYSQL_TDIGEST_H */