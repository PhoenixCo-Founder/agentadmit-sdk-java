package com.agentadmit;

/**
 * 1.15.0: the result of {@link TokensClient#createOwnerLink(String, String)}.
 *
 * <p>{@link #ownerSessionUrl()} opens a pending confirm-each-time request for
 * the app's own signed-in user: the user creates a passkey (when they have
 * none yet) and confirms on that page; on a computer the page can show a QR
 * code to continue on the user's phone. The URL is for that user's browser
 * only. Do not return it to an agent and do not log it; the SDK does not log
 * it either, and {@link #toString()} leaves it out.
 *
 * @param actionSessionId    the action session the link opens
 * @param ownerSessionUrl    the page for the signed-in user
 * @param enrollmentRequired {@code true} (201) when the user has no passkey on
 *                           file for the app yet and creates one on the page;
 *                           {@code false} (200) when a passkey is already on
 *                           file and the URL is the ordinary confirmation page
 * @param enrollmentReason   {@code no_passkey} or {@code no_eligible_authenticator}
 *                           when enrollment is required, otherwise {@code null}
 * @param expiresAt          ISO-8601 expiry of the action session
 */
public record OwnerLink(
    String actionSessionId,
    String ownerSessionUrl,
    boolean enrollmentRequired,
    String enrollmentReason,
    String expiresAt
) {
    /**
     * Leaves {@code ownerSessionUrl} out so a logged result never carries it.
     *
     * @return a description without the owner session URL
     */
    @Override
    public String toString() {
        return "OwnerLink[actionSessionId=" + actionSessionId
            + ", enrollmentRequired=" + enrollmentRequired
            + ", enrollmentReason=" + enrollmentReason
            + ", expiresAt=" + expiresAt + "]";
    }
}
