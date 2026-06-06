package ch.jens.access;

import java.util.Set;

public record ResourcePolicy(
        String resource,
        Set<String> requiredRoles,
        boolean requiresMfa,
        boolean businessHoursOnly,
        Set<String> allowedIpPrefixes
) {}
