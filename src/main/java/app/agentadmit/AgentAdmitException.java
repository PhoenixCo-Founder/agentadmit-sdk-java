package app.agentadmit;

/**
 * Exception thrown by AgentAdmit SDK operations.
 */
public class AgentAdmitException extends RuntimeException {
    private final int statusCode;

    public AgentAdmitException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() { return statusCode; }
}
