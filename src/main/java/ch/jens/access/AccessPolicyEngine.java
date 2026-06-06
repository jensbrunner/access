package ch.jens.access;

import java.time.Clock;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AccessPolicyEngine {

    private static final LocalTime BUSINESS_HOURS_START = LocalTime.of(8, 0);
    private static final LocalTime BUSINESS_HOURS_END = LocalTime.of(18, 0);
    private final Map<String, List<ResourcePolicy>> policiesByResource = new HashMap<>();
    private final Clock clock;

    public AccessPolicyEngine(List<ResourcePolicy> policies, Clock clock) {
        for (ResourcePolicy policy : policies) {
            policiesByResource.computeIfAbsent(policy.resource(), key -> new ArrayList<>())
                .add(policy);
        }
        this.clock = clock;
    }

    public AccessDecision evaluate(AccessRequest request) {
        validateRequest(request);

        List<ResourcePolicy> policies = policiesByResource.get(request.resource());

        if (policies == null) {
            return new AccessDecision(false, List.of("Unknown resource"));
        }

        if (request.user().blocked()) {
            return new AccessDecision(false, List.of("User is blocked"));
        }

        List<String> results = new ArrayList<>();

        for (ResourcePolicy policy : policies) {
            List<String> reasons = evaluatePolicy(policy, request);
            if (reasons.isEmpty()) {
                return new AccessDecision(true, List.of("Access granted"));
            }
            results.add(String.join(", ", reasons));
        }   

        return new AccessDecision(false, results);
    }

    private List<String> evaluatePolicy(ResourcePolicy policy, AccessRequest request) {
        List<String> reasons = new ArrayList<>();
        
        if (!hasRequiredRole(request.user(), policy)) {
            reasons.add("Missing required role: " + policy.requiredRoles());
        }

        if(policy.requiresMfa() && !request.user().mfaVerified()){
            reasons.add("MFA required");
        }

        if(policy.businessHoursOnly() && !isWithinBusinessHours()){
            reasons.add("Outside business hours");
        }
    
        if (!isIpAllowed(request.ipAddress(), policy)) {
            reasons.add("IP address not allowed");
        }

        return reasons;
    }

    private boolean isIpAllowed(String ip, ResourcePolicy policy) {

        if (policy.allowedIpPrefixes().isEmpty()) {
            return true;
        }

        for (String validPrefix : policy.allowedIpPrefixes()) {
            if (ip.startsWith(validPrefix)) {
                return true;
            }
        }
        
        return false;
    }

    private boolean isWithinBusinessHours() {
        LocalTime now = LocalTime.now(clock);
        return !now.isBefore(BUSINESS_HOURS_START) && now.isBefore(BUSINESS_HOURS_END);
    }

    private boolean hasRequiredRole(User user, ResourcePolicy policy) { 
        if (policy.requiredRoles().isEmpty()) {
            return true;
        }
        
        for (String userRole : user.roles()) {
            if (policy.requiredRoles().contains(userRole)) {
                return true;
            }
        }

        return false;
    }

    private void validateRequest(AccessRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("AccessRequest cannot be null.");
        }
        if (request.user() == null){
            throw new IllegalArgumentException("AccessRequest.User cannot be null.");
        }
        if (request.resource() == null || request.resource().isBlank()) {
            throw new IllegalArgumentException("AccessRequest.Resource cannot be null or blank.");
        }
        if (request.ipAddress() == null || request.ipAddress().isBlank()){
            throw new IllegalArgumentException("AccessRequest.IPAddress cannot be null or blank.");
        }
        if (request.user().username() == null || request.user().username().isBlank()) {
            throw new IllegalArgumentException("AccessRequest.User.Username cannot be null or blank.");
        }
    }
}
