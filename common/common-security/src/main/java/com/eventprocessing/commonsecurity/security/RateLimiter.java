package com.eventprocessing.commonsecurity.security;

import lombok.extern.slf4j.Slf4j;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class RateLimiter {

    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final int capacity;
    private final Duration refillDuration;

    public RateLimiter(int requestsPerWindow, Duration windowDuration) {
        this.capacity = requestsPerWindow;
        this.refillDuration = windowDuration;
    }

    public boolean allowRequest(String key) {
        TokenBucket bucket = buckets.computeIfAbsent(key, k -> new TokenBucket(capacity, refillDuration));
        return bucket.tryConsume();
    }

    public int getRemainingRequests(String key) {
        TokenBucket bucket = buckets.get(key);
        return bucket != null ? bucket.getAvailableTokens() : capacity;
    }

    public void reset(String key) {
        buckets.remove(key);
    }

    public void resetAll() {
        buckets.clear();
    }

    private static class TokenBucket {
        private final int capacity;
        private final Duration refillDuration;
        private final AtomicInteger tokens;
        private volatile Instant lastRefillTime;

        public TokenBucket(int capacity, Duration refillDuration) {
            this.capacity = capacity;
            this.refillDuration = refillDuration;
            this.tokens = new AtomicInteger(capacity);
            this.lastRefillTime = Instant.now();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens.get() > 0) {
                tokens.decrementAndGet();
                return true;
            }
            return false;
        }

        public int getAvailableTokens() {
            return tokens.get();
        }

        private void refill() {
            Instant now = Instant.now();
            Duration timeSinceLastRefill = Duration.between(lastRefillTime, now);

            if (timeSinceLastRefill.compareTo(refillDuration) >= 0) {
                tokens.set(capacity);
                lastRefillTime = now;
            }
        }
    }
}