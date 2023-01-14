package br.com.appodontologia.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public final class ExceptionResolver {

	private ExceptionResolver() {
	}

	public static String getRootException(Throwable ex) {
		return String.format("%s in class: %s Line: %s", ExceptionUtils.getRootCauseMessage(ex),
				ExceptionUtils.getRootCause(ex).getStackTrace()[0].getClassName(),
				ExceptionUtils.getRootCause(ex).getStackTrace()[0].getLineNumber());
	}

	public static void getRootException(HttpStatus status, HttpServletRequest request,
									    HttpServletResponse response, String error,
									    String message) throws IOException {
		response.reset();
		response.setContentType("application/json;charset=UTF-8");
		response.setStatus(status.value());
		response.getWriter().write(new ObjectMapper().writeValueAsString(new BusinessException(System.currentTimeMillis(),
				status.value(), error, message, request.getRequestURI())));
	}
}
