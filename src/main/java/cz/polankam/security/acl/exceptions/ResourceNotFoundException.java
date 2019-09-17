package cz.polankam.security.acl.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception which is thrown in case of resource not found.
 *
 * Created by Martin Polanka
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class ResourceNotFoundException extends RuntimeException {

    /**
     * Construct exception with given cause message.
     * @param message description of error
     */
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
