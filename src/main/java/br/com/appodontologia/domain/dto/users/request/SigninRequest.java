package br.com.appodontologia.domain.dto.users.request;

import br.com.appodontologia.util.Constants;
import io.swagger.annotations.ApiModelProperty;
import lombok.*;

import javax.validation.constraints.NotEmpty;
import java.io.Serializable;

@Data
@Builder
@ToString
@AllArgsConstructor
@NoArgsConstructor
public class SigninRequest implements Serializable {
	private static final long serialVersionUID = 7086810874058978087L;

	@NotEmpty(message = Constants.MESSAGE_FILL + Constants.FIELD_EMAIL + Constants.MESSAGE_REQUIRE)
	@ApiModelProperty(value = "E-mail do usuário", example = "rodrigo@msn.com", required = true, position = 1)
	private String email;

	@NotEmpty(message = Constants.MESSAGE_FILL + Constants.FIELD_PASSWORD + Constants.MESSAGE_REQUIRE)
	@ApiModelProperty(value = "Senha do usuário", example = "123Aa$Aa", required = true, position = 2)
	private String password;
}
