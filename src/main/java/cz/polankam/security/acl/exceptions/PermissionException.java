package cz.polankam.security.acl.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception which is thrown in case of error within library.
 *
 * Created by Martin Polanka
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class PermissionException extends RuntimeException {

    /**
     * Construct exception with given cause message.
     * @param message description of error
     */
    public PermissionException(String message) {
        super(message);
    }
}
