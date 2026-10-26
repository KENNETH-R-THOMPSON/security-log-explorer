package com.kenneth.security;

import java.time.Instant;

/** One synthetic authentication event. */
public record LoginEvent(Instant timestamp, String user, String address, boolean success) {}
