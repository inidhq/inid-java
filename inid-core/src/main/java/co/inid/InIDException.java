package co.inid;

/**
 * A failure talking to InID or checking what it sent. {@code status} is InID's HTTP status,
 * or 0 when InID couldn't be reached (or there was no HTTP status at all).
 */
public class InIDException extends RuntimeException {
    private final String code;
    private final int status;

    public InIDException(String code) {
        this(code, 0);
    }

    public InIDException(String code, int status) {
        super(code);
        this.code = code;
        this.status = status;
    }

    public InIDException(String code, int status, Throwable cause) {
        super(code, cause);
        this.code = code;
        this.status = status;
    }

    public String code() { return code; }
    public int status() { return status; }
}
