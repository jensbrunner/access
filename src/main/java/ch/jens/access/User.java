package ch.jens.access;

import java.util.Set;

public record User(
        String username,
        Set<String> roles,
        boolean mfaVerified,
        boolean blocked 
) {}
