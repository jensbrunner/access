package ch.jens.access;

import java.util.List;

public record AccessDecision(
        boolean allowed,
        List<String> reasons
) {}
