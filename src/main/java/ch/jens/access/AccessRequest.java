package ch.jens.access;

public record AccessRequest(
        User user,
        String resource,
        String ipAddress
) {}
