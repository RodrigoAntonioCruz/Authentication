package br.com.appodontologia.domain.dto.users.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse implements Serializable {
	private static final long serialVersionUID = -3013893615498524385L;
	private String token;
}
