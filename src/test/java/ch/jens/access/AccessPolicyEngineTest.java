package ch.jens.access;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class AccessPolicyEngineTest {

    private final Clock clock = Clock.fixed(
        Instant.parse("2026-05-15T09:00:00Z"),
        ZoneId.of("Europe/Zurich")
    );

    private final ResourcePolicy policy = new ResourcePolicy(
            "/admin",
            Set.of("ADMIN"),
            false,
            false,
            Set.of()
    );

    private final AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);
    private final User validUser = new User("jens", Set.of("ADMIN"),  true, false);
    private final AccessRequest validRequest = new AccessRequest(validUser, "/admin", "10.0.0.1");

    @Test
    void rejectsNullRequest() {
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(null));
    }

    @Test
    void rejectsNullUser() {
        AccessRequest invalidRequest = new AccessRequest(null, "/admin", "10.0.0.1");
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void rejectsNullResource() {
        AccessRequest invalidRequest = new AccessRequest(validUser, null, "10.0.0.1");
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void rejectsBlankResource() {
        AccessRequest invalidRequest = new AccessRequest(validUser, "     ", "10.0.0.1");
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void rejectsNullIp() {
        AccessRequest invalidRequest = new AccessRequest(validUser, "/admin", null);
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void rejectsBlankIp() {
        AccessRequest invalidRequest = new AccessRequest(validUser, "/admin", " ");
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void rejectsNullUsername() {
        User invalidUser = new User(null, Set.of("ADMIN"), true, false);
        AccessRequest invalidRequest = new AccessRequest(invalidUser, "/admin", "10.0.0.1");
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void rejectsBlankUsername() {
        User invalidUser = new User("   ", Set.of("ADMIN"), true, false);
        AccessRequest invalidRequest = new AccessRequest(invalidUser, "/admin", "10.0.0.1");
        assertThrows(IllegalArgumentException.class, () -> engine.evaluate(invalidRequest));
    }

    @Test
    void denyWithoutMatchingPolicy() {
        AccessRequest request = new AccessRequest(validUser, "/unknown", "10.0.0.1");
        AccessDecision expected = new AccessDecision(false, List.of("Unknown resource"));
        AccessDecision actual = engine.evaluate(request);
        assertEquals(expected, actual);
    }

    @Test
    void blockedUserIsDeniedImmediately() {
        User blockedUser = new User("jens", Set.of("ADMIN"), true, true);
        AccessRequest request = new AccessRequest(blockedUser, "/admin", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);
        assertFalse(decision.allowed());
        assertEquals(List.of("User is blocked"), decision.reasons());
    }

    @Test
    void allowsUserWithRequiredRole() {
        AccessDecision decision = engine.evaluate(validRequest);
        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void allowsUserWithOneOfRequiredRoles() {
        ResourcePolicy policy = new ResourcePolicy(
            "/support",
            Set.of("SUPPORT", "ADMIN"),
            false,
            false,
            Set.of("10.0.0.1")
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);
        User user = new User("jens", Set.of("SUPPORT"), true, false);
        AccessRequest request = new AccessRequest(user, "/support", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);
        assertTrue(decision.allowed());
    }

    @Test
    void deniesIfUserHasNoneOfRequiredRoles() {
        User user = new User("jens", Set.of("USER"), true, false);
        AccessRequest request = new AccessRequest(user, "/admin", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);
        assertFalse(decision.allowed());
        assertEquals(List.of("Missing required role: [ADMIN]"), decision.reasons());
    }

    @Test
    void allowsIfNoRoleRequired() {
        ResourcePolicy policy = new ResourcePolicy(
                "/admin",
                Set.of(),
                false,
                false,
                Set.of()
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);

        User user = new User("jens", Set.of(), true, false);
        AccessRequest request = new AccessRequest(user, "/admin", "10.0.0.1");

        AccessDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void deniesIfMfaRequiredButNotVerified() {
        ResourcePolicy policy = new ResourcePolicy(
            "/admin",
            Set.of("ADMIN"),
            true,
            false,
            Set.of("10.0.0.1")
        );

        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);
        User user = new User("jens", Set.of("ADMIN"), false, false);
        AccessRequest request = new AccessRequest(user, "/admin", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);
        assertFalse(decision.allowed());
        assertEquals(List.of("MFA required"), decision.reasons());
    }

    @Test
    void allowsIfMfaRequiredAndVerified() {
        ResourcePolicy policy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                true,
                false,
                Set.of()
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);

        User user = new User("jens", Set.of("ADMIN"), true, false);
        AccessRequest request = new AccessRequest(user, "/admin", "10.0.0.1");

        AccessDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void allowsIfOnePolicyDoesNotRequireMfa() {

        ResourcePolicy mfaPolicy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                true,
                false,
                Set.of()
        );
        ResourcePolicy nonMfaPolicy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                false,
                false,
                Set.of()
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(mfaPolicy, nonMfaPolicy), clock);
        User user = new User("jens", Set.of("ADMIN"), false, false);
        AccessRequest request = new AccessRequest(user, "/admin", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void allowsDuringBusinessHours() {
        ResourcePolicy policy = new ResourcePolicy(
            "/admin",
            Set.of("ADMIN"),
            false,
            true,
            Set.of()
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clockAt(9, 0));
        AccessRequest request = new AccessRequest(validUser, "/admin", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);
        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void rejectBeforeBusinessHours() {
        ResourcePolicy policy = new ResourcePolicy(
            "/admin",
            Set.of("ADMIN"),
            false,
            true,
            Set.of()
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clockAt(7, 59));
        AccessRequest request = new AccessRequest(validUser, "/admin", "10.0.0.1");
        AccessDecision decision = engine.evaluate(request);
        assertFalse(decision.allowed());
        assertEquals(List.of("Outside business hours"), decision.reasons());
    }

    @Test
    void allowsMatchingIpPrefix() {
        ResourcePolicy policy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                false,
                false,
                Set.of("10.0.")
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);

        User user = new User("jens", Set.of("ADMIN"), true, false);
        AccessRequest request = new AccessRequest(user, "/admin", "10.0.12.5");

        AccessDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void deniesNonMatchingIpPrefix() {
        ResourcePolicy policy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                false,
                false,
                Set.of("10.0.")
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);

        User user = new User("jens", Set.of("ADMIN"), true, false);
        AccessRequest request = new AccessRequest(user, "/admin", "203.0.113.5");

        AccessDecision decision = engine.evaluate(request);

        assertFalse(decision.allowed());
        assertEquals(List.of("IP address not allowed"), decision.reasons());
    }

    @Test
    void allowsAnyIpIfNoPrefixesConfigured() {
        ResourcePolicy policy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                false,
                false,
                Set.of()
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(policy), clock);

        User user = new User("jens", Set.of("ADMIN"), true, false);
        AccessRequest request = new AccessRequest(user, "/admin", "203.0.113.5");

        AccessDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    private Clock clockAt(int hour, int minute) {
        return Clock.fixed(
            ZonedDateTime.of(2026, 
                5, 
                15,
                hour,
                minute, 
                0, 
                0, 
                ZoneId.of("Europe/Zurich"))
                .toInstant(),
            ZoneId.of("Europe/Zurich"));
    }

    @Test
    void grantsAccessIfOnePolicyPasses() {
        ResourcePolicy adminPolicy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                true,
                false,
                Set.of("10.0.")
        );
        ResourcePolicy supportPolicy = new ResourcePolicy(
                "/admin",
                Set.of("SUPPORT"),
                false,
                false,
                Set.of("192.168.")
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(adminPolicy, supportPolicy), clock);

        User user = new User("jens", Set.of("SUPPORT"), false, false);
        AccessRequest request = new AccessRequest(user, "/admin", "192.168.1.20");

        AccessDecision decision = engine.evaluate(request);

        assertTrue(decision.allowed());
        assertEquals(List.of("Access granted"), decision.reasons());
    }

    @Test
    void deniesWithOneReasonPerFailedPolicy() {
        ResourcePolicy adminPolicy = new ResourcePolicy(
                "/admin",
                Set.of("ADMIN"),
                true,
                false,
                Set.of("10.0.")
        );
        ResourcePolicy supportPolicy = new ResourcePolicy(
                "/admin",
                Set.of("SUPPORT"),
                false,
                false,
                Set.of("192.168.")
        );
        AccessPolicyEngine engine = new AccessPolicyEngine(List.of(adminPolicy, supportPolicy), clock);

        User user = new User("jens", Set.of("USER"), false, false);
        AccessRequest request = new AccessRequest(user, "/admin", "203.0.113.5");

        AccessDecision decision = engine.evaluate(request);

        assertFalse(decision.allowed());
        assertEquals(2, decision.reasons().size());
    }
}
