package com.eventprocessing.commondto.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Core Event DTO representing an event in the system
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Event {

    private String eventId;

    @NotBlank(message = "Workspace ID is required")
    private String workspaceId;

    @NotBlank(message = "Event type is required")
    private String eventType;

    @NotNull(message = "Timestamp is required")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private Instant timestamp;

    @NotBlank(message = "Source is required")
    private String source;

    @NotNull(message = "Event data is required")
    private Map<String, Object> data;

    private List<String> tags;
    private EventMetadata metadata;
    private EventSeverity severity;
    private EventStatus status;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private Instant ingestionTime;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", timezone = "UTC")
    private Instant processingTime;

    /**
     * Generate a unique event ID
     */
    public void generateEventId() {
        this.eventId = "evt_" + UUID.randomUUID().toString();
    }

    /**
     * Mark event as ingested with current timestamp
     */
    public void markAsIngested() {
        this.ingestionTime = Instant.now();
        this.status = EventStatus.INGESTED;
    }

    /**
     * Mark event as processed with current timestamp
     */
    public void markAsProcessed() {
        this.processingTime = Instant.now();
        this.status = EventStatus.PROCESSED;
    }

    /**
     * Mark event as failed
     */
    public void markAsFailed() {
        this.status = EventStatus.FAILED;
    }

    /**
     * Event severity levels
     */
    public enum EventSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    /**
     * Event processing status
     */
    public enum EventStatus {
        RECEIVED,    // Event received by API
        INGESTED,    // Event written to Kafka
        VALIDATED,   // Event validated
        PROCESSED,   // Event processed successfully
        FAILED,      // Event processing failed
        ARCHIVED     // Event archived
    }
}