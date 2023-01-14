package br.com.appodontologia.domain.dto.users.request;


import br.com.appodontologia.util.Constants;
import br.com.appodontologia.validator.UserValidator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import java.io.Serializable;
import java.util.Set;


@Data
@Builder
@ApiModel
@UserValidator
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequest implements Serializable {
    private static final long serialVersionUID = 6016806597527015535L;

    @NotEmpty(message = Constants.MESSAGE_FILL + Constants.FIELD_NAME + Constants.MESSAGE_REQUIRE)
    @Length(min=3, max=120, message=Constants.LENGTH_FIELD)
    @ApiModelProperty(value = "Nome completo do usuário", example = "Rodrigo Antonio Cruz", required = true, position = 1)
    private String username;

    @Email(message = Constants.ERROR_INVALID_EMAIL)
    @NotEmpty(message = Constants.MESSAGE_FILL + Constants.FIELD_EMAIL + Constants.MESSAGE_REQUIRE)
    @ApiModelProperty(value = "E-mail do usuário", example = "rodrigo@msn.com", required = true, position = 2)
    private String email;

    @Length(min=8, message=Constants.LENGTH_MIN_PASSWORD)
    @NotEmpty(message = Constants.MESSAGE_FILL + Constants.FIELD_PASSWORD + Constants.MESSAGE_REQUIRE)
    @ApiModelProperty(value = "Senha do usuário", example = "123Aa$Aa", required = true, position = 3)
    private String password;

    @ApiModelProperty(value = "Confirmação de senha do usuário", example = "123Aa$Aa", required = true, position = 4)
    private String confirm_password;

    @NotEmpty(message = Constants.MESSAGE_FILL + Constants.FIELD_ROLES + Constants.MESSAGE_REQUIRE)
    @ApiModelProperty(value = "Perfil de usuário", example = "[ROLE_USER]", required = true, position = 5)
    private Set<String> roles;
}