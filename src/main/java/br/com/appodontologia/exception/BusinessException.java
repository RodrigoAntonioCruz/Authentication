package br.com.appodontologia.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@EqualsAndHashCode(callSuper = false)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class BusinessException implements Serializable {
	private static final long serialVersionUID = 1L;

	private Long timestamp;
	private Integer httpStatus;
	private String error;
	private String message;
	private String path;

	public BusinessException(Long timestamp, Integer httpStatus, String error, String message, String path) {
		super();
		this.timestamp = timestamp;
		this.httpStatus = httpStatus;
		this.error = error;
		this.message = message;
		this.path = path;
	}

	private final List<FieldMessage> errors = new ArrayList<>();

	public void addError(String fieldName, String messagem) {
		errors.add(new FieldMessage(fieldName, messagem));
	}
}
