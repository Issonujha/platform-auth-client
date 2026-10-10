package com.dukaandaar.auth.client;

/** Thrown when a platform token is missing, malformed, wrongly signed or expired. */
public class PlatformTokenException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public PlatformTokenException(String message) {
		super(message);
	}

	public PlatformTokenException(String message, Throwable cause) {
		super(message, cause);
	}
}
